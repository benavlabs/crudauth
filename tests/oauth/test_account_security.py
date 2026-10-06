"""OAuth callback account resolution: claiming, refusals, error codes and throttling."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi import FastAPI

from crudauth import AuthHooks, CookieConfig, CRUDAuth, OAuthCredentials, SessionTransport
from crudauth.exceptions import OAuthAccountException
from crudauth.ratelimit import RateLimit
from crudauth.oauth import AbstractOAuthProvider, OAuthProviderFactory, OAuthUserInfo
from crudauth.repository import UserRepository
from crudauth.utils import get_password_hash, is_unusable_password

SECRET = "test-secret-key-0123456789-0123456789"


class ProfileProvider(AbstractOAuthProvider):
    profile: dict[str, Any] = {}
    token: Any = {"access_token": "provider-access"}
    raw_user_info: Any = None

    def __init__(self, client_id, client_secret, redirect_uri, scopes=None):
        super().__init__(
            client_id,
            client_secret,
            redirect_uri,
            scopes=["email"],
            authorize_endpoint="https://idp.example/authorize",
            token_endpoint="https://idp.example/token",
            userinfo_endpoint="https://idp.example/userinfo",
            provider_name="stub",
        )

    async def exchange_code(self, code, code_verifier=None, headers=None):
        return type(self).token

    async def get_user_info(self, access_token):
        if type(self).raw_user_info is not None:
            return type(self).raw_user_info
        return dict(type(self).profile)

    async def process_user_info(self, user_info: dict[str, Any]) -> OAuthUserInfo:
        return OAuthUserInfo(
            provider="stub",
            provider_user_id=str(user_info.get("id")),
            email=user_info.get("email"),
            email_verified=user_info.get("verified", True),
        )


@pytest.fixture(autouse=True)
def provider(monkeypatch):
    monkeypatch.setitem(OAuthProviderFactory._providers, "stub", ProfileProvider)
    monkeypatch.setattr(ProfileProvider, "profile", {})
    monkeypatch.setattr(ProfileProvider, "token", {"access_token": "provider-access"})
    monkeypatch.setattr(ProfileProvider, "raw_user_info", None)
    return ProfileProvider


def _app(get_session, UserModel, **options: Any) -> tuple[CRUDAuth, FastAPI]:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        oauth={"stub": OAuthCredentials(client_id="id", client_secret="secret")},
        redirect_base_url="http://test",
        **options,
    )
    app = FastAPI()
    app.include_router(auth.router)
    return auth, app


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def _sign_in(client: httpx.AsyncClient, json_mode: bool = False) -> httpx.Response:
    authorize = await client.get("/oauth/stub/authorize")
    url = authorize.json()["url"] if json_mode else authorize.headers["location"]
    state = parse_qs(urlparse(url).query)["state"][0]
    return await client.get(f"/oauth/stub/callback?code=abc&state={state}")


def _error(response: httpx.Response) -> str:
    return parse_qs(urlparse(response.headers["location"]).query)["error"][0]


async def test_a_verified_provider_email_claims_an_unverified_password_account(
    get_session, UserModel, sessionmaker, provider
) -> None:
    auth, app = _app(get_session, UserModel)
    repo = UserRepository(UserModel)
    await auth.initialize()
    async with _client(app) as squatter, _client(app) as owner:
        await squatter.post(
            "/register",
            json={"email": "owner@x.com", "username": "squatter", "password": "squatter-pw"},
        )
        await squatter.post("/login", data={"username": "squatter", "password": "squatter-pw"})
        provider.profile = {"id": "owner-idp", "email": "owner@x.com"}
        callback = await _sign_in(owner)
        owner_me = await owner.get("/me")
        squatter_me = await squatter.get("/me")
        password_login = await squatter.post(
            "/login", data={"username": "squatter", "password": "squatter-pw"}
        )
    await auth.shutdown()

    assert callback.status_code == 307 and "error" not in callback.headers["location"]
    assert owner_me.status_code == 200
    assert (squatter_me.status_code, password_login.status_code) == (401, 401)
    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "owner@x.com")
    assert repo.email_verified(user) is True
    assert is_unusable_password(repo.get(user, "hashed_password"))
    assert repo.token_version(user) == 1
    assert repo.get(user, "stub_id") == "owner-idp"


async def test_linking_a_verified_account_keeps_its_password_and_sessions(
    get_session, UserModel, sessionmaker, provider
) -> None:
    auth, app = _app(get_session, UserModel)
    repo = UserRepository(UserModel)
    await auth.initialize()
    async with sessionmaker() as db:
        await repo.create(
            db,
            {
                "email": "owner@x.com",
                "username": "owner",
                "hashed_password": get_password_hash("owner-pw"),
                "email_verified": True,
            },
        )
    async with _client(app) as browser, _client(app) as other:
        await browser.post("/login", data={"username": "owner", "password": "owner-pw"})
        provider.profile = {"id": "owner-idp", "email": "owner@x.com"}
        callback = await _sign_in(other)
        password_session = await browser.get("/me")
    await auth.shutdown()

    assert "error" not in callback.headers["location"]
    assert password_session.status_code == 200
    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "owner@x.com")
    assert repo.get(user, "stub_id") == "owner-idp"
    assert repo.token_version(user) == 0
    assert not is_unusable_password(repo.get(user, "hashed_password"))


@pytest.mark.parametrize(
    ("profile", "code"),
    [
        ({"id": "idp-1", "email": "new@x.com", "verified": False}, "email_unverified"),
        ({"id": "idp-1"}, "email_missing"),
    ],
)
@pytest.mark.parametrize("json_mode", [False, True])
async def test_account_resolution_failures_report_their_code(
    get_session, UserModel, sessionmaker, provider, profile, code, json_mode
) -> None:
    options = {"oauth_response_mode": "json"} if json_mode else {}
    auth, app = _app(get_session, UserModel, **options)
    await auth.initialize()
    provider.profile = profile
    async with _client(app) as browser:
        callback = await _sign_in(browser, json_mode)
        me = await browser.get("/me")
    await auth.shutdown()

    if json_mode:
        assert (callback.status_code, callback.json()) == (400, {"detail": code})
    else:
        assert (callback.status_code, _error(callback)) == (307, code)
    assert me.status_code == 401
    async with sessionmaker() as db:
        assert await UserRepository(UserModel).get_by_oauth(db, "stub", "idp-1") is None


async def test_an_account_linked_to_another_provider_identity_is_not_relinked(
    get_session, UserModel, sessionmaker, provider
) -> None:
    auth, app = _app(get_session, UserModel)
    repo = UserRepository(UserModel)
    await auth.initialize()
    async with _client(app) as first, _client(app) as second:
        provider.profile = {"id": "idp-first", "email": "shared@x.com"}
        await _sign_in(first)
        provider.profile = {"id": "idp-second", "email": "shared@x.com"}
        callback = await _sign_in(second)
        me = await second.get("/me")
    await auth.shutdown()

    assert _error(callback) == "provider_already_linked"
    assert me.status_code == 401
    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "shared@x.com")
    assert repo.get(user, "stub_id") == "idp-first"


async def test_an_inactive_account_gets_no_session(
    get_session, UserModel, sessionmaker, provider
) -> None:
    logins: list[dict[str, Any]] = []
    hooks = AuthHooks(on_after_login=lambda user, **kwargs: logins.append(user))
    auth, app = _app(get_session, UserModel, hooks=hooks)
    repo = UserRepository(UserModel)
    await auth.initialize()
    async with sessionmaker() as db:
        await repo.create(
            db,
            {
                "email": "off@x.com",
                "username": "off",
                "hashed_password": get_password_hash("off-pw"),
                "email_verified": True,
                "is_active": False,
            },
        )
        user_id = repo.user_id(await repo.get_by_email(db, "off@x.com"))
    provider.profile = {"id": "idp-off", "email": "off@x.com"}
    async with _client(app) as browser:
        callback = await _sign_in(browser)
    sessions = await auth.sessions.list_for_user(user_id)
    await auth.shutdown()

    assert _error(callback) == "account_inactive"
    assert "session_id=" not in " ".join(callback.headers.get_list("set-cookie"))
    assert (logins, sessions) == ([], [])


@pytest.mark.parametrize("verified", [True, False], ids=["verified", "unverified"])
async def test_a_sign_in_on_an_inactive_account_writes_nothing_to_it(
    get_session, UserModel, sessionmaker, provider, verified
) -> None:
    """Refused before linking: no provider id, and an unverified account isn't claimed."""
    auth, app = _app(get_session, UserModel)
    repo = UserRepository(UserModel)
    await auth.initialize()
    async with sessionmaker() as db:
        await repo.create(
            db,
            {
                "email": "gone@x.com",
                "username": "gone",
                "hashed_password": get_password_hash("gone-pw"),
                "email_verified": verified,
                "is_active": False,
            },
        )
    provider.profile = {"id": "idp-gone", "email": "gone@x.com"}
    async with _client(app) as browser:
        callback = await _sign_in(browser)
    await auth.shutdown()

    assert _error(callback) == "account_inactive"
    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "gone@x.com")
    assert repo.get(user, "stub_id") is None
    assert repo.get(user, "oauth_provider") is None
    assert repo.email_verified(user) is verified
    assert not is_unusable_password(repo.get(user, "hashed_password"))
    assert repo.token_version(user) == 0


async def test_the_service_refuses_an_inactive_account_found_by_provider_id(
    get_session, UserModel, sessionmaker, provider
) -> None:
    """An app driving ``get_or_create_user`` itself gets the refusal, not the user."""
    auth, _ = _app(get_session, UserModel)
    repo = UserRepository(UserModel)
    await auth.initialize()
    async with sessionmaker() as db:
        await repo.create(
            db,
            {
                "email": "linked@x.com",
                "username": "linked",
                "hashed_password": get_password_hash("linked-pw"),
                "email_verified": True,
                "is_active": False,
                "stub_id": "idp-linked",
            },
        )
        info = OAuthUserInfo(
            provider="stub",
            provider_user_id="idp-linked",
            email="linked@x.com",
            email_verified=True,
        )
        assert auth.oauth is not None
        with pytest.raises(OAuthAccountException) as refused:
            await auth.oauth.get_or_create_user(info, db)
    await auth.shutdown()

    assert refused.value.code == "account_inactive"


@pytest.mark.parametrize(
    ("token", "raw_user_info"),
    [(["not", "an", "object"], None), ({"access_token": "tok"}, ["not", "an", "object"])],
)
async def test_provider_responses_that_are_not_objects_fail_the_sign_in(
    get_session, UserModel, provider, token, raw_user_info
) -> None:
    auth, app = _app(get_session, UserModel)
    await auth.initialize()
    provider.token = token
    provider.raw_user_info = raw_user_info
    async with _client(app) as browser:
        callback = await _sign_in(browser)
    await auth.shutdown()

    assert _error(callback) == "oauth_failed"


async def test_authorize_is_rate_limited(get_session, UserModel) -> None:
    auth, app = _app(get_session, UserModel, rate_limits={"oauth_authorize": RateLimit(2, 60)})
    await auth.initialize()
    async with _client(app) as browser:
        statuses = [(await browser.get("/oauth/stub/authorize")).status_code for _ in range(3)]
    await auth.shutdown()

    assert statuses == [307, 307, 429]


async def test_the_login_hook_names_the_oauth_session_by_its_public_handle(
    get_session, UserModel, provider
) -> None:
    handles: list[str | None] = []
    hooks = AuthHooks(
        on_after_login=lambda user, *, request, context: handles.append(context.session_handle)
    )
    auth, app = _app(get_session, UserModel, hooks=hooks)
    await auth.initialize()
    provider.profile = {"id": "idp-handle", "email": "handle@x.com"}
    async with _client(app) as browser:
        await _sign_in(browser)
        session_id = browser.cookies.get("session_id")
    await auth.shutdown()

    assert session_id is not None
    assert handles == [auth.sessions.session_handle(session_id)]
