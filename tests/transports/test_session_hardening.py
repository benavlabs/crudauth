"""Sessions: private ids, logout, version binding, concurrent writes, cross-site logins."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import fakeredis.aioredis
import httpx
import pytest
from fastapi import Depends, FastAPI, Request
from starlette.requests import Request as StarletteRequest

from crudauth import (
    AuthContext,
    BearerTransport,
    CookieConfig,
    CRUDAuth,
    Principal,
    SessionTransport,
    SudoConfig,
    Transport,
)
from crudauth import sudo as sudo_module
from crudauth.ratelimit import KeyBy, RateLimit
from crudauth.repository import UserRepository
from crudauth.transports.session.schemas import SessionData
from crudauth.utils import get_password_hash

SECRET = "test-secret-key-0123456789-0123456789"
PASSWORD = "pw123456"


def _request() -> StarletteRequest:
    return StarletteRequest(
        {"type": "http", "method": "GET", "headers": [], "client": ("1.2.3.4", 1234)}
    )


def _app(auth: CRUDAuth) -> FastAPI:
    app = FastAPI()
    app.include_router(auth.router)
    return app


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def _auth(get_session, UserModel, transports: list[Transport] | None = None, **options: Any):
    return CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=transports
        or [SessionTransport(cookies=CookieConfig(secure=False), management_routes=True)],
        **options,
    )


async def _register_and_login(client: httpx.AsyncClient, username: str = "alice") -> str:
    await client.post(
        "/register",
        json={"email": f"{username}@x.com", "username": username, "password": PASSWORD},
    )
    login = await client.post("/login", data={"username": username, "password": PASSWORD})
    return login.json()["csrf_token"]


async def test_the_device_list_never_returns_a_usable_session_id(get_session, UserModel) -> None:
    auth = _auth(get_session, UserModel)
    app = _app(auth)
    await auth.initialize()
    async with _client(app) as first, _client(app) as second, _client(app) as thief:
        await _register_and_login(first)
        await second.post("/login", data={"username": "alice", "password": PASSWORD})
        listed = [row["id"] for row in (await first.get("/sessions")).json()]
        cookies = {first.cookies["session_id"], second.cookies["session_id"]}
        thief.cookies.set("session_id", listed[0])
        stolen = await thief.get("/me")
    await auth.shutdown()

    assert len(listed) == 2
    assert not cookies & set(listed)
    assert stolen.status_code == 401


@pytest.mark.parametrize("backend", ["memory", "redis"])
async def test_an_owner_revokes_a_session_with_a_uuid_primary_key(
    get_session, UserModel, backend
) -> None:
    options: dict[str, Any] = (
        {"redis_client": fakeredis.aioredis.FakeRedis()} if backend == "redis" else {}
    )
    auth = _auth(get_session, UserModel, warn_on_memory_backend=False, **options)
    owner = uuid.uuid4()
    session_id, _ = await auth.sessions.create_session(_request(), user_id=owner)

    assert await auth.sessions.revoke(session_id, owner_id=owner) is True
    assert await auth.sessions.storage.get(session_id, SessionData) is None


async def test_logout_also_clears_the_bearer_refresh_cookie(get_session, UserModel) -> None:
    auth = _auth(
        get_session,
        UserModel,
        [
            SessionTransport(cookies=CookieConfig(secure=False)),
            BearerTransport(refresh="cookie", cookies=CookieConfig(secure=False)),
        ],
    )
    app = _app(auth)
    await auth.initialize()
    async with _client(app) as browser:
        csrf = await _register_and_login(browser)
        await browser.post("/token", data={"username": "alice", "password": PASSWORD})
        assert "refresh_token" in browser.cookies
        logout = await browser.post("/logout", headers={"X-CSRF-Token": csrf})
        refresh = await browser.post("/refresh")
    await auth.shutdown()

    assert logout.status_code == 200
    assert "refresh_token" not in browser.cookies
    assert refresh.status_code == 401


@pytest.mark.parametrize(("refresh", "mounted"), [("cookie", True), ("body", False)])
async def test_a_bearer_only_app_can_clear_its_refresh_cookie(
    get_session, UserModel, refresh, mounted
) -> None:
    auth = _auth(
        get_session,
        UserModel,
        [BearerTransport(refresh=refresh, cookies=CookieConfig(secure=False))],
    )
    app = _app(auth)
    await auth.initialize()
    async with _client(app) as browser:
        await browser.post(
            "/register", json={"email": "a@x.com", "username": "alice", "password": PASSWORD}
        )
        await browser.post("/token", data={"username": "alice", "password": PASSWORD})
        logout = await browser.post("/logout")
    await auth.shutdown()

    if mounted:
        assert logout.status_code == 200
        assert "refresh_token" not in browser.cookies
    else:
        assert logout.status_code == 404


async def test_logout_after_the_session_expired_clears_the_cookies(get_session, UserModel) -> None:
    auth = _auth(get_session, UserModel)
    app = _app(auth)
    await auth.initialize()
    async with _client(app) as browser:
        csrf = await _register_and_login(browser)
        await auth.sessions.storage.delete(browser.cookies["session_id"])
        await auth.sessions.csrf_storage.delete(csrf)
        logout = await browser.post("/logout", headers={"X-CSRF-Token": csrf})
    await auth.shutdown()

    assert logout.status_code == 200
    assert "session_id" not in browser.cookies


class RenamingTransport(Transport):
    name = "apikey"

    async def authenticate(self, request: Request, ctx: AuthContext) -> Principal | None:
        if request.headers.get("x-api-key") != "key":
            return None
        user = await ctx.resolve_user(1)
        if user is None:
            return None
        return ctx.build_principal(user_id=ctx.repo.user_id(user), user=user, transport="api_key")


async def test_a_transport_may_label_its_principal_differently(
    get_session, UserModel, sessionmaker
) -> None:
    auth = _auth(get_session, UserModel, [RenamingTransport()])
    app = _app(auth)

    @app.post(
        "/action",
        dependencies=[Depends(auth.rate_limit("action", RateLimit(5, 60), key=KeyBy.USER_OR_IP))],
    )
    async def action(principal: Principal = Depends(auth.current_user())):
        return {"transport": principal.transport}

    async with sessionmaker() as db:
        await auth.repo.create(
            db, {"email": "a@x.com", "username": "alice", "hashed_password": get_password_hash("x")}
        )
    async with _client(app) as client:
        response = await client.post("/action", headers={"x-api-key": "key"})

    assert (response.status_code, response.json()) == (200, {"transport": "api_key"})


async def test_an_activity_update_keeps_a_sudo_lockout_that_landed_mid_request(
    get_session, UserModel, sessionmaker, monkeypatch
) -> None:
    auth = _auth(
        get_session, UserModel, redis_client=fakeredis.aioredis.FakeRedis(), sudo=SudoConfig()
    )
    sudo = auth.sudo
    assert sudo is not None
    async with sessionmaker() as db:
        user = await auth.repo.create(
            db,
            {
                "email": "a@x.com",
                "username": "alice",
                "hashed_password": get_password_hash(PASSWORD),
            },
        )
    user_id = auth.repo.user_id(user)
    session_id, _ = await auth.sessions.create_session(_request(), user_id=user_id)
    principal = Principal(
        user_id=user_id, transport="session", user=user, metadata={"session_id": session_id}
    )
    await sudo.elevate(principal, PASSWORD)
    storage = auth.sessions.storage
    read = storage.get

    async def read_then_lock_out(key: str, model: Any) -> Any:
        value = await read(key, model)
        await sudo._clear_elevation(session_id)
        return value

    monkeypatch.setattr(storage, "get", read_then_lock_out)
    await auth.sessions.validate_session(session_id, update_activity=True)
    monkeypatch.setattr(storage, "get", read)

    assert await sudo.is_elevated(principal) is False


async def test_concurrent_sudo_guesses_share_the_attempt_cap(
    get_session, UserModel, sessionmaker, monkeypatch
) -> None:
    auth = _auth(get_session, UserModel, sudo=SudoConfig(max_attempts=3))
    sudo = auth.sudo
    assert sudo is not None and sudo.backend is not None
    backend = sudo.backend
    for name in ("get_ttl", "increment"):
        original = getattr(backend, name)

        async def yielding(*args: Any, _original: Any = original) -> Any:
            await asyncio.sleep(0)
            return await _original(*args)

        monkeypatch.setattr(backend, name, yielding)
    checked: list[str] = []
    real_verify = sudo_module.verify_password_async

    async def counting_verify(password: str, hashed: str | None) -> bool:
        checked.append(password)
        return await real_verify(password, hashed)

    monkeypatch.setattr(sudo_module, "verify_password_async", counting_verify)
    async with sessionmaker() as db:
        user = await auth.repo.create(
            db,
            {
                "email": "a@x.com",
                "username": "alice",
                "hashed_password": get_password_hash(PASSWORD),
            },
        )
    user_id = auth.repo.user_id(user)
    session_id, _ = await auth.sessions.create_session(_request(), user_id=user_id)
    principal = Principal(
        user_id=user_id, transport="session", user=user, metadata={"session_id": session_id}
    )

    await asyncio.gather(
        *(sudo.elevate(principal, f"guess-{i}") for i in range(10)), return_exceptions=True
    )

    assert len(checked) <= 3


async def test_a_session_created_after_a_credential_change_from_an_older_check_is_rejected(
    get_session, UserModel, sessionmaker
) -> None:
    auth = _auth(get_session, UserModel)
    app = _app(auth)
    repo = UserRepository(UserModel)
    await auth.initialize()
    async with sessionmaker() as db:
        user = await repo.create(
            db,
            {
                "email": "a@x.com",
                "username": "alice",
                "hashed_password": get_password_hash(PASSWORD),
            },
        )
        checked_version = repo.token_version(user)
        await repo.increment_token_version(db, user)
    user_id = repo.user_id(user)
    stale, _ = await auth.sessions.create_session(
        _request(), user_id=user_id, token_version=checked_version
    )
    current, _ = await auth.sessions.create_session(
        _request(), user_id=user_id, token_version=checked_version + 1
    )
    unbound, _ = await auth.sessions.create_session(_request(), user_id=user_id)
    statuses = {}
    async with _client(app) as browser:
        for name, session_id in (("stale", stale), ("current", current), ("unbound", unbound)):
            browser.cookies.set("session_id", session_id)
            statuses[name] = (await browser.get("/me")).status_code
    await auth.shutdown()

    assert statuses == {"stale": 401, "current": 200, "unbound": 200}


async def test_concurrent_token_version_bumps_both_count(UserModel, sessionmaker) -> None:
    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        created = await repo.create(
            db, {"email": "a@x.com", "username": "alice", "hashed_password": "h"}
        )
    user_id = repo.user_id(created)
    async with sessionmaker() as first_db, sessionmaker() as second_db:
        first = await repo.get_by_id(first_db, user_id)
        second = await repo.get_by_id(second_db, user_id)
        await repo.increment_token_version(first_db, first)
        await repo.increment_token_version(second_db, second)
    async with sessionmaker() as db:
        assert repo.token_version(await repo.get_by_id(db, user_id)) == 2


@pytest.mark.parametrize(
    ("path", "transports"),
    [
        ("/login", [SessionTransport(cookies=CookieConfig(secure=False))]),
        ("/token", [BearerTransport(refresh="cookie", cookies=CookieConfig(secure=False))]),
    ],
)
async def test_a_cross_site_login_is_refused(get_session, UserModel, path, transports) -> None:
    auth = _auth(get_session, UserModel, transports)
    app = _app(auth)
    await auth.initialize()
    body = {"username": "alice", "password": PASSWORD}
    async with _client(app) as browser:
        await browser.post(
            "/register", json={"email": "a@x.com", "username": "alice", "password": PASSWORD}
        )
        cross_site = await browser.post(path, data=body, headers={"Sec-Fetch-Site": "cross-site"})
        same_site = await browser.post(path, data=body, headers={"Sec-Fetch-Site": "same-site"})
    await auth.shutdown()

    assert (cross_site.status_code, same_site.status_code) == (403, 200)
    assert "set-cookie" not in cross_site.headers


async def test_a_cross_site_token_request_without_a_refresh_cookie_is_allowed(
    get_session, UserModel
) -> None:
    auth = _auth(get_session, UserModel, [BearerTransport(refresh="body")])
    app = _app(auth)
    await auth.initialize()
    async with _client(app) as client:
        await client.post(
            "/register", json={"email": "a@x.com", "username": "alice", "password": PASSWORD}
        )
        response = await client.post(
            "/token",
            data={"username": "alice", "password": PASSWORD},
            headers={"Sec-Fetch-Site": "cross-site"},
        )
    await auth.shutdown()

    assert response.status_code == 200


async def test_terminated_sessions_leave_no_csrf_records(get_session, UserModel) -> None:
    client = fakeredis.aioredis.FakeRedis()
    auth = _auth(get_session, UserModel, redis_client=client)
    app = _app(auth)
    await auth.initialize()
    async with _client(app) as first, _client(app) as second, _client(app) as third:
        csrf = await _register_and_login(first)
        await second.post("/login", data={"username": "alice", "password": PASSWORD})
        await third.post("/login", data={"username": "alice", "password": PASSWORD})
        listed = (await first.get("/sessions")).json()
        other = next(row["id"] for row in listed if not row["current"])
        await first.delete(f"/sessions/{other}", headers={"X-CSRF-Token": csrf})
        await first.post("/logout-all", headers={"X-CSRF-Token": csrf})
        await first.post("/logout", headers={"X-CSRF-Token": csrf})
    await auth.shutdown()

    keys = [key.decode() if isinstance(key, bytes) else key for key in await client.keys("*")]
    assert [key for key in keys if key.startswith(("session:", "csrf"))] == []


async def test_expired_sessions_are_pruned_from_the_user_index(get_session, UserModel) -> None:
    client = fakeredis.aioredis.FakeRedis()
    auth = _auth(get_session, UserModel, redis_client=client)
    manager = auth.sessions
    expired, _ = await manager.create_session(_request(), user_id=5)
    live, _ = await manager.create_session(_request(), user_id=5)
    await client.delete(f"session:{manager.session_handle(expired)}")

    listed = await manager.list_for_user(5)

    assert [row["id"] for row in listed] == [manager.session_handle(live)]
    assert await manager.storage.get_user_sessions(5) == [manager.session_handle(live)]
