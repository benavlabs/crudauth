"""``on_oauth_login``: the provider profile and the request's db on every OAuth sign-in."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select, text, update

from crudauth import AuthHooks, CookieConfig, CRUDAuth, OAuthCredentials, SessionTransport
from crudauth.oauth import OAuthUserInfo
from crudauth.oauth.providers.github import GitHubOAuthProvider
from crudauth.repository import UserRepository
from crudauth.utils import get_password_hash
from tests.conftest import User

SECRET = "test-secret-key-0123456789-0123456789"
PROFILE: dict[str, Any] = {
    "id": 4242,
    "login": "Octo-Cat",
    "name": "Octo Cat",
    "avatar_url": "https://avatars.example/4242",
    "emails": [{"email": "octo@x.com", "primary": True, "verified": True}],
}


class _GitHub(GitHubOAuthProvider):
    """GitHub's own profile normalization, without the network."""

    profile: dict[str, Any] = PROFILE
    exchange: dict[str, Any] = {"access_token": "gh-token"}

    async def exchange_code(self, code, code_verifier=None, headers=None):
        return dict(self.exchange)

    async def get_user_info(self, access_token):
        return dict(self.profile)


@pytest.fixture
def github(monkeypatch: pytest.MonkeyPatch) -> type[_GitHub]:
    from crudauth.oauth import OAuthProviderFactory

    monkeypatch.setitem(OAuthProviderFactory._providers, "github", _GitHub)
    monkeypatch.setattr(_GitHub, "profile", dict(PROFILE))
    monkeypatch.setattr(_GitHub, "exchange", {"access_token": "gh-token"})
    return _GitHub


def _app(
    get_session: Any, UserModel: Any, hooks: AuthHooks, **options: Any
) -> tuple[CRUDAuth, FastAPI]:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        oauth={"github": OAuthCredentials(client_id="id", client_secret="secret")},
        redirect_base_url="http://test",
        hooks=hooks,
        warn_on_memory_backend=False,
        **options,
    )
    app = FastAPI()
    app.include_router(auth.router)
    return auth, app


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def _sign_in(browser: httpx.AsyncClient, state: str | None = None) -> httpx.Response:
    authorize = await browser.get("/oauth/github/authorize")
    location = authorize.headers.get("location") or authorize.json()["url"]
    issued = parse_qs(urlparse(location).query)["state"][0]
    return await browser.get(f"/oauth/github/callback?code=abc&state={state or issued}")


def _recorder(calls: list[dict[str, Any]]) -> Any:
    async def on_oauth_login(
        user: dict, info: OAuthUserInfo, *, db: Any, created: bool, context: Any
    ) -> None:
        calls.append({"user": user, "info": info, "db": db, "created": created, "context": context})

    return on_oauth_login


async def test_the_hook_gets_the_github_login_and_whether_the_account_is_new(
    get_session: Any, UserModel: Any, github: type[_GitHub]
) -> None:
    calls: list[dict[str, Any]] = []
    _, app = _app(get_session, UserModel, AuthHooks(on_oauth_login=_recorder(calls)))

    async with _client(app) as browser:
        first = await _sign_in(browser)
        second = await _sign_in(browser)

    assert first.status_code == second.status_code == 307
    assert [call["created"] for call in calls] == [True, False]
    info = calls[0]["info"]
    assert info.provider == "github"
    assert info.provider_user_id == "4242"
    assert info.username == "Octo-Cat"
    assert info.raw_data["login"] == "Octo-Cat"
    assert calls[0]["user"]["email"] == "octo@x.com"
    assert calls[0]["db"] is not None
    assert calls[0]["context"].transport == "oauth"
    assert calls[0]["context"].session_handle is None


async def test_the_hook_runs_when_the_sign_in_links_an_existing_account_by_email(
    get_session: Any, UserModel: Any, sessionmaker: Any, github: type[_GitHub]
) -> None:
    async with sessionmaker() as db:
        await UserRepository(UserModel).create(
            db,
            {
                "email": "octo@x.com",
                "username": "octo",
                "hashed_password": get_password_hash("a-password-1"),
                "email_verified": True,
            },
        )
    calls: list[dict[str, Any]] = []
    _, app = _app(get_session, UserModel, AuthHooks(on_oauth_login=_recorder(calls)))

    async with _client(app) as browser:
        response = await _sign_in(browser)

    assert response.status_code == 307
    assert [call["created"] for call in calls] == [False]
    assert calls[0]["user"]["username"] == "octo"


async def test_a_write_the_hook_commits_persists_and_follows_a_rename(
    get_session: Any, UserModel: Any, sessionmaker: Any, github: type[_GitHub]
) -> None:
    """The storefront's case: keep the current GitHub login, refreshed on every sign-in."""

    async def record_login(
        user: dict, info: OAuthUserInfo, *, db: Any, created: bool, context: Any
    ) -> None:
        await db.execute(update(User).where(User.id == user["id"]).values(full_name=info.username))
        await db.commit()

    _, app = _app(get_session, UserModel, AuthHooks(on_oauth_login=record_login))

    async with _client(app) as browser:
        await _sign_in(browser)
        github.profile = {**PROFILE, "login": "Renamed-Cat"}
        await _sign_in(browser)
        me = await browser.get("/me")

    async with sessionmaker() as db:
        stored = (await db.execute(select(User.full_name))).scalars().all()
    assert me.status_code == 200
    assert stored == ["Renamed-Cat"]


async def test_the_json_mode_runs_the_hook_too(
    get_session: Any, UserModel: Any, github: type[_GitHub]
) -> None:
    calls: list[dict[str, Any]] = []
    _, app = _app(
        get_session,
        UserModel,
        AuthHooks(on_oauth_login=_recorder(calls)),
        oauth_response_mode="json",
    )

    async with _client(app) as browser:
        response = await _sign_in(browser)

    assert response.status_code == 200
    assert [call["info"].username for call in calls] == ["Octo-Cat"]


async def test_the_hook_does_not_run_for_a_disabled_account(
    get_session: Any, UserModel: Any, sessionmaker: Any, github: type[_GitHub]
) -> None:
    async with sessionmaker() as db:
        await UserRepository(UserModel).create(
            db,
            {
                "email": "octo@x.com",
                "username": "octo",
                "hashed_password": get_password_hash("a-password-1"),
                "email_verified": True,
                "is_active": False,
            },
        )
    calls: list[dict[str, Any]] = []
    _, app = _app(get_session, UserModel, AuthHooks(on_oauth_login=_recorder(calls)))

    async with _client(app) as browser:
        response = await _sign_in(browser)

    assert "error=account_inactive" in response.headers["location"]
    assert calls == []


async def test_the_hook_does_not_run_for_an_account_created_disabled(
    get_session: Any, UserModel: Any, github: type[_GitHub], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An app whose model creates accounts disabled (awaiting approval, say): the callback
    refuses the new account after ``on_after_register``, and ``on_oauth_login`` never runs."""
    monkeypatch.setattr(UserRepository, "is_active", lambda self, user: False)
    calls: list[dict[str, Any]] = []
    _, app = _app(get_session, UserModel, AuthHooks(on_oauth_login=_recorder(calls)))

    async with _client(app) as browser:
        response = await _sign_in(browser)

    assert "error=account_inactive" in response.headers["location"]
    assert calls == []


async def test_the_hook_does_not_run_for_a_state_this_browser_did_not_start(
    get_session: Any, UserModel: Any, github: type[_GitHub]
) -> None:
    calls: list[dict[str, Any]] = []
    _, app = _app(get_session, UserModel, AuthHooks(on_oauth_login=_recorder(calls)))

    async with _client(app) as browser:
        response = await _sign_in(browser, state="forged")

    assert "error=invalid_state" in response.headers["location"]
    assert calls == []


async def test_the_hook_does_not_run_when_the_token_exchange_fails(
    get_session: Any, UserModel: Any, github: type[_GitHub]
) -> None:
    github.exchange = {"error": "bad_verification_code"}
    calls: list[dict[str, Any]] = []
    _, app = _app(get_session, UserModel, AuthHooks(on_oauth_login=_recorder(calls)))

    async with _client(app) as browser:
        response = await _sign_in(browser)

    assert "error=oauth_failed" in response.headers["location"]
    assert calls == []


async def test_a_hook_that_raises_leaves_the_sign_in_standing_and_its_write_undone(
    get_session: Any, UserModel: Any, sessionmaker: Any, github: type[_GitHub]
) -> None:
    """Best-effort like every hook; crudauth rolls back what it left so the sign-in goes on."""

    async def failing(user: dict, info: Any, *, db: Any, created: bool, context: Any) -> None:
        await db.execute(update(User).where(User.id == user["id"]).values(full_name="half"))
        await db.execute(text("INSERT INTO users (id) VALUES (NULL)"))

    _, app = _app(get_session, UserModel, AuthHooks(on_oauth_login=failing))

    async with _client(app) as browser:
        response = await _sign_in(browser)
        me = await browser.get("/me")

    async with sessionmaker() as db:
        stored = (await db.execute(select(User.full_name))).scalars().all()
    assert response.status_code == 307
    assert me.status_code == 200
    assert stored == [None]


@pytest.mark.parametrize("hook", ["on_after_register", "on_oauth_login"])
async def test_a_hook_that_rolls_back_does_not_break_the_sign_in(
    get_session: Any, UserModel: Any, github: type[_GitHub], hook: str
) -> None:
    """The hooks guide tells a hook to roll back on its own failure; that used to expire the
    user crudauth went on reading, and the callback raised ``MissingGreenlet``."""

    async def rolls_back(*args: Any, db: Any, **kwargs: Any) -> None:
        await db.rollback()

    _, app = _app(get_session, UserModel, AuthHooks(**{hook: rolls_back}))

    async with _client(app) as browser:
        response = await _sign_in(browser)
        me = await browser.get("/me")

    assert response.status_code == 307
    assert me.status_code == 200
