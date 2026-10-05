"""OAuth end-to-end with a stub provider (no network), incl. account linking."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi import FastAPI

from crudauth import CRUDAuth, CookieConfig, OAuthCredentials, SessionTransport
from crudauth.oauth import AbstractOAuthProvider, OAuthProviderFactory, OAuthUserInfo


class StubProvider(AbstractOAuthProvider):
    """A provider that returns canned data instead of calling the network."""

    def __init__(self, client_id, client_secret, redirect_uri, scopes=None):
        super().__init__(
            client_id,
            client_secret,
            redirect_uri,
            scopes=scopes or ["read"],
            authorize_endpoint="https://stub.example/authorize",
            token_endpoint="https://stub.example/token",
            userinfo_endpoint="https://stub.example/userinfo",
            provider_name="stub",
        )

    async def exchange_code(self, code, code_verifier=None, headers=None):
        return {"access_token": "stub-access", "token_type": "Bearer"}

    async def get_user_info(self, access_token):
        return {"id": "stub-123", "email": "oauthuser@x.com", "name": "OAuth User"}

    async def process_user_info(self, user_info) -> OAuthUserInfo:
        return OAuthUserInfo(
            provider="stub",
            provider_user_id=str(user_info["id"]),
            email=user_info.get("email"),
            email_verified=True,
            name=user_info.get("name"),
            username=None,
            raw_data=user_info,
        )


OAuthProviderFactory.register_provider("stub", StubProvider)


@pytest.fixture
async def client(get_session, UserModel):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        oauth={"stub": OAuthCredentials(client_id="id", client_secret="sec")},
        redirect_base_url="http://test",
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c
    await auth.shutdown()


@pytest.fixture
async def json_client(get_session, UserModel):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        oauth={"stub": OAuthCredentials(client_id="id", client_secret="sec")},
        redirect_base_url="http://test",
        oauth_response_mode="json",
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c
    await auth.shutdown()


async def test_full_oauth_callback_creates_user_and_session(client) -> None:
    # 1. authorize → 307 to provider, carrying state
    r = await client.get("/oauth/stub/authorize?redirect_to=/dashboard")
    assert r.status_code == 307
    location = r.headers["location"]
    state = parse_qs(urlparse(location).query)["state"][0]

    # 2. callback → creates user, establishes session, redirects to redirect_to
    r = await client.get(f"/oauth/stub/callback?code=abc&state={state}")
    assert r.status_code == 307
    assert r.headers["location"] == "/dashboard"
    # session cookie was set
    assert "session_id" in r.cookies or any(
        "session_id" in c for c in r.headers.get_list("set-cookie")
    )

    # 3. the session authenticates /me
    r = await client.get("/me")
    assert r.status_code == 200
    assert r.json()["email"] == "oauthuser@x.com"
    assert r.json()["via"] == "session"


async def test_invalid_state_rejected(client) -> None:
    r = await client.get("/oauth/stub/callback?code=abc&state=nope", follow_redirects=False)
    assert r.status_code == 307
    assert r.headers["location"] == "http://test?error=invalid_state"


async def test_authorize_sets_state_binding_cookie(client) -> None:
    r = await client.get("/oauth/stub/authorize")
    set_cookie = " ".join(r.headers.get_list("set-cookie"))
    assert "oauth_state=" in set_cookie
    assert "httponly" in set_cookie.lower()


async def test_json_authorize_and_callback_keep_cookies(json_client) -> None:
    r = await json_client.get("/oauth/stub/authorize?redirect_to=/dashboard")
    assert r.status_code == 200
    assert r.json()["url"].startswith("https://stub.example/authorize")
    state = parse_qs(urlparse(r.json()["url"]).query)["state"][0]
    assert "oauth_state=" in " ".join(r.headers.get_list("set-cookie"))

    r = await json_client.get(f"/oauth/stub/callback?code=abc&state={state}")
    assert r.status_code == 200
    assert r.json()["user"]["email"] == "oauthuser@x.com"
    assert r.json()["csrf_token"]
    assert r.json()["redirect_to"] == "/dashboard"
    assert "session_id=" in " ".join(r.headers.get_list("set-cookie"))
    assert set(r.json()["user"]) == {"user_id", "username", "email", "is_superuser"}


async def test_json_callback_requires_state_cookie(json_client) -> None:
    r = await json_client.get("/oauth/stub/authorize")
    state = parse_qs(urlparse(r.json()["url"]).query)["state"][0]
    json_client.cookies.clear()

    r = await json_client.get(f"/oauth/stub/callback?code=abc&state={state}")
    assert r.status_code == 400


async def test_json_callback_provider_error_returns_json_400(json_client) -> None:
    r = await json_client.get("/oauth/stub/callback?error=access_denied&state=whatever")
    assert r.status_code == 400
    assert r.json() == {"detail": "oauth_failed"}
    assert "location" not in r.headers


@pytest.fixture
async def custom_path_client(get_session, UserModel):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        oauth={"stub": OAuthCredentials(client_id="id", client_secret="sec")},
        redirect_base_url="http://test",
        oauth_paths={
            "prefix": "/api/v1/auth/oauth",
            "authorize_path": "/{provider}",
            "callback_path": "/callback/{provider}",
        },
        oauth_response_mode="json",
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c
    await auth.shutdown()


async def test_custom_oauth_paths_match_provider_redirect_uri(custom_path_client) -> None:
    r = await custom_path_client.get("/api/v1/auth/oauth/stub")
    assert r.status_code == 200
    query = parse_qs(urlparse(r.json()["url"]).query)
    assert query["redirect_uri"] == ["http://test/api/v1/auth/oauth/callback/stub"]
    state = query["state"][0]
    r = await custom_path_client.get(f"/api/v1/auth/oauth/callback/stub?code=abc&state={state}")
    assert r.status_code == 200


@pytest.mark.parametrize(
    ("oauth_paths", "message"),
    [
        ({"authorize_path": "/login"}, r"must contain '\{provider\}'"),
        ({"callback_path": "/callback"}, r"must contain '\{provider\}'"),
        ({"callbak_path": "/{provider}/cb"}, "callbak_path"),
    ],
)
def test_invalid_oauth_paths_fail_fast(get_session, UserModel, oauth_paths, message) -> None:
    with pytest.raises(ValueError, match=message):
        CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY="test-secret-key-0123456789-0123456789",
            transports=[SessionTransport(cookies=CookieConfig(secure=False))],
            oauth={"stub": OAuthCredentials(client_id="id", client_secret="sec")},
            redirect_base_url="http://test",
            oauth_paths=oauth_paths,
        )


def test_oauth_provider_without_id_column_fails_fast(get_session, UserModel) -> None:
    # A provider whose {name}_id column is missing on the model must raise at
    # startup, not silently fail to persist/match the provider id at login.
    OAuthProviderFactory.register_provider("gitlab", StubProvider)
    with pytest.raises(ValueError, match="gitlab_id"):
        CRUDAuth(
            session=get_session,
            user_model=UserModel,  # has google_id/github_id/stub_id, but no gitlab_id
            SECRET_KEY="test-secret-key-0123456789-0123456789",
            transports=[SessionTransport(cookies=CookieConfig(secure=False))],
            oauth={"gitlab": OAuthCredentials(client_id="i", client_secret="s")},
            redirect_base_url="http://test",
        )


async def test_callback_requires_browser_bound_state(client) -> None:
    # browser A starts the flow: state stored server-side + binder cookie set on A
    r = await client.get("/oauth/stub/authorize?redirect_to=/dashboard")
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]

    # a different browser (no binder cookie) replays the captured callback URL
    client.cookies.clear()
    r = await client.get(f"/oauth/stub/callback?code=abc&state={state}", follow_redirects=False)
    assert r.headers["location"] == "http://test?error=invalid_state"  # not bound to this browser

    # /me confirms no session was established for the would-be victim
    assert (await client.get("/me")).status_code == 401


async def test_callback_provider_error_redirects(client) -> None:
    # provider redirects back with ?error= (e.g. user declined) → graceful
    # redirect, not a 422 for the now-missing code.
    r = await client.get("/oauth/stub/callback?error=access_denied&state=whatever")
    assert r.status_code == 307
    assert "error=oauth_failed" in r.headers["location"]
    assert (await client.get("/me")).status_code == 401


async def test_callback_missing_code_redirects(client) -> None:
    r = await client.get("/oauth/stub/callback?state=whatever")
    assert r.status_code == 307
    assert "error=oauth_failed" in r.headers["location"]


async def _start_flow(client) -> str:
    r = await client.get("/oauth/stub/authorize")
    return parse_qs(urlparse(r.headers["location"]).query)["state"][0]


async def test_callback_missing_access_token_redirects(client, monkeypatch) -> None:
    # some providers (e.g. GitHub) signal failure with HTTP 200 + an error body
    # and no access_token → must not KeyError into a 500.
    async def no_token(self, code, code_verifier=None, headers=None):
        return {"error": "bad_verification_code"}

    monkeypatch.setattr(StubProvider, "exchange_code", no_token)
    state = await _start_flow(client)
    r = await client.get(f"/oauth/stub/callback?code=abc&state={state}")
    assert r.status_code == 307
    assert "error=oauth_failed" in r.headers["location"]
    assert (await client.get("/me")).status_code == 401


async def test_callback_exchange_http_error_redirects(client, monkeypatch) -> None:
    async def boom(self, code, code_verifier=None, headers=None):
        raise httpx.ConnectError("provider down")

    monkeypatch.setattr(StubProvider, "exchange_code", boom)
    state = await _start_flow(client)
    r = await client.get(f"/oauth/stub/callback?code=abc&state={state}")
    assert r.status_code == 307
    assert "error=oauth_failed" in r.headers["location"]
    assert (await client.get("/me")).status_code == 401


async def test_callback_userinfo_parse_error_redirects(client, monkeypatch) -> None:
    # a malformed 200 userinfo that breaks the provider's parser (KeyError) must
    # redirect, not 500.
    async def bad_parse(self, user_info):
        raise KeyError("id")

    monkeypatch.setattr(StubProvider, "process_user_info", bad_parse)
    state = await _start_flow(client)
    r = await client.get(f"/oauth/stub/callback?code=abc&state={state}")
    assert r.status_code == 307
    assert "error=oauth_failed" in r.headers["location"]
    assert (await client.get("/me")).status_code == 401


@pytest.fixture
async def app_path_client(get_session, UserModel):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        oauth={"stub": OAuthCredentials(client_id="id", client_secret="sec")},
        redirect_base_url="http://test",
        oauth_default_redirect="/app/login",
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c
    await auth.shutdown()


async def test_a_failure_lands_on_the_default_redirect(app_path_client) -> None:
    r = await app_path_client.get("/oauth/stub/callback?error=access_denied&state=whatever")
    assert r.status_code == 307
    assert r.headers["location"] == "/app/login?error=oauth_failed"


async def test_an_unsafe_redirect_to_lands_on_the_default_redirect(app_path_client) -> None:
    r = await app_path_client.get("/oauth/stub/authorize?redirect_to=https://evil.example/x")
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]

    r = await app_path_client.get(f"/oauth/stub/callback?code=abc&state={state}")
    assert r.headers["location"] == "/app/login"
    assert (await app_path_client.get("/me")).status_code == 200


async def test_a_safe_redirect_to_still_wins_over_the_default(app_path_client) -> None:
    r = await app_path_client.get("/oauth/stub/authorize?redirect_to=/app/dashboard")
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]

    r = await app_path_client.get(f"/oauth/stub/callback?code=abc&state={state}")
    assert r.headers["location"] == "/app/dashboard"


async def test_the_provider_redirect_uri_ignores_the_default_redirect(app_path_client) -> None:
    r = await app_path_client.get("/oauth/stub/authorize")
    query = parse_qs(urlparse(r.headers["location"]).query)
    assert query["redirect_uri"] == ["http://test/oauth/stub/callback"]


@pytest.mark.parametrize(
    "target", ["//evil.example", "app/login", "javascript:alert(1)", "/\\evil"]
)
def test_an_unsafe_default_redirect_fails_fast(get_session, UserModel, target) -> None:
    with pytest.raises(ValueError, match="oauth_default_redirect"):
        CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY="test-secret-key-0123456789-0123456789",
            transports=[SessionTransport(cookies=CookieConfig(secure=False))],
            oauth={"stub": OAuthCredentials(client_id="id", client_secret="sec")},
            redirect_base_url="http://test",
            oauth_default_redirect=target,
        )


def test_an_absolute_default_redirect_is_accepted(get_session, UserModel) -> None:
    CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        oauth={"stub": OAuthCredentials(client_id="id", client_secret="sec")},
        redirect_base_url="http://api.test",
        oauth_default_redirect="https://app.test/login",
    )
