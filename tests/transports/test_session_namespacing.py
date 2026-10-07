"""Two crudauth apps side by side, and sessions kept in a store the app supplies."""

from __future__ import annotations

from typing import Any

import fakeredis.aioredis
import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import create_async_engine

from crudauth import CookieConfig, CRUDAuth, DatabaseStore, SessionTransport
from crudauth.ratelimit import (
    LockoutConfig,
    MemoryRateLimiterBackend,
    RedisBackend,
    redis_rate_limiter,
)
from crudauth.repository import UserRepository
from crudauth.storage import MemorySessionStorage
from crudauth.transports.session.schemas import CSRFToken, SessionData
from crudauth.utils import get_password_hash

SECRET = "test-secret-key-0123456789-0123456789"
PASSWORD = "namespaced-pass-1"
ADMIN: dict[str, Any] = {
    "cookie_name": "admin_session",
    "csrf_cookie_name": "admin_csrf",
    "storage_prefix": "admin:session:",
    "csrf_storage_prefix": "admin:csrf:",
}
LOCKOUT = LockoutConfig(max_attempts=2)


def _app(get_session, UserModel, transport: SessionTransport) -> tuple[CRUDAuth, FastAPI]:
    auth = CRUDAuth(
        session=get_session, user_model=UserModel, SECRET_KEY=SECRET, transports=[transport]
    )
    app = FastAPI()
    app.include_router(auth.router)
    return auth, app


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def _user(sessionmaker, UserModel) -> None:
    async with sessionmaker() as db:
        await UserRepository(UserModel).create(
            db,
            {
                "email": "both@x.com",
                "username": "both",
                "hashed_password": get_password_hash(PASSWORD),
                "email_verified": True,
            },
        )


async def _login(client: httpx.AsyncClient) -> httpx.Response:
    return await client.post("/login", data={"username": "both", "password": PASSWORD})


@pytest.mark.parametrize(
    ("admin_options", "crosses"), [({}, True), (ADMIN, False)], ids=["shared", "own"]
)
async def test_one_apps_session_is_not_accepted_by_the_other_on_a_shared_redis(
    get_session, UserModel, sessionmaker, admin_options: dict[str, Any], crosses: bool
) -> None:
    """With the default names both apps read one key space; with their own, neither sees the other's."""
    redis = fakeredis.aioredis.FakeRedis()
    cookies = CookieConfig(secure=False)
    main, main_app = _app(
        get_session, UserModel, SessionTransport(redis_client=redis, cookies=cookies)
    )
    admin, admin_app = _app(
        get_session,
        UserModel,
        SessionTransport(redis_client=redis, cookies=cookies, **admin_options),
    )
    await main.initialize()
    await admin.initialize()
    await _user(sessionmaker, UserModel)

    async with _client(main_app) as browser:
        assert (await _login(browser)).status_code == 200
        main_session = browser.cookies.get("session_id")
    assert main_session is not None
    admin_cookie = admin_options.get("cookie_name", "session_id")
    async with _client(admin_app) as intruder:
        intruder.cookies.set(admin_cookie, main_session)
        me = await intruder.get("/me")
    await main.shutdown()
    await admin.shutdown()
    await redis.aclose()

    assert (me.status_code == 200) is crosses


async def test_both_apps_stay_signed_in_in_one_browser(
    get_session, UserModel, sessionmaker
) -> None:
    """Distinct cookie names, so the second login doesn't overwrite the first."""
    cookies = CookieConfig(secure=False)
    main, main_app = _app(get_session, UserModel, SessionTransport(cookies=cookies))
    admin, admin_app = _app(get_session, UserModel, SessionTransport(cookies=cookies, **ADMIN))
    await main.initialize()
    await admin.initialize()
    await _user(sessionmaker, UserModel)

    async with _client(main_app) as on_main, _client(admin_app) as on_admin:
        await _login(on_main)
        await _login(on_admin)
        on_admin.cookies.update(on_main.cookies)
        on_main.cookies.update(on_admin.cookies)
        main_me = await on_main.get("/me")
        admin_me = await on_admin.get("/me")
        admin_cookies = {cookie.name for cookie in on_admin.cookies.jar}
    await main.shutdown()
    await admin.shutdown()

    assert (main_me.status_code, admin_me.status_code) == (200, 200)
    assert {"session_id", "csrf_token", "admin_session", "admin_csrf"} <= admin_cookies


async def test_an_admin_app_writes_under_its_own_prefixes(
    get_session, UserModel, sessionmaker
) -> None:
    redis = fakeredis.aioredis.FakeRedis()
    admin, admin_app = _app(
        get_session,
        UserModel,
        SessionTransport(redis_client=redis, cookies=CookieConfig(secure=False), **ADMIN),
    )
    await admin.initialize()
    await _user(sessionmaker, UserModel)

    async with _client(admin_app) as browser:
        await _login(browser)
    keys = sorted(key.decode() if isinstance(key, bytes) else key for key in await redis.keys("*"))
    await admin.shutdown()
    await redis.aclose()

    assert keys
    assert all(key.startswith("admin:") for key in keys), keys
    assert not any(key.startswith(("session:", "csrf:")) for key in keys), keys


async def test_sessions_live_in_the_store_the_app_supplied(
    get_session, UserModel, sessionmaker
) -> None:
    sessions: MemorySessionStorage[SessionData] = MemorySessionStorage(prefix="db:session:")
    tokens: MemorySessionStorage[CSRFToken] = MemorySessionStorage(prefix="db:csrf:")
    auth, app = _app(
        get_session,
        UserModel,
        SessionTransport(cookies=CookieConfig(secure=False), storage=sessions, csrf_storage=tokens),
    )
    await auth.initialize()
    await _user(sessionmaker, UserModel)

    async with _client(app) as browser:
        signed_in = await _login(browser)
        session_id = browser.cookies.get("session_id")
        me = await browser.get("/me")
    stored = await sessions.get(auth.sessions.session_handle(session_id), SessionData)
    await auth.shutdown()

    assert (signed_in.status_code, me.status_code) == (200, 200)
    assert stored is not None
    assert auth.sessions.storage is sessions


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"cookie_name": "same", "csrf_cookie_name": "same"}, "cookie_name and csrf_cookie_name"),
        (
            {"storage_prefix": "p:", "csrf_storage_prefix": "p:"},
            "storage_prefix and csrf_storage_prefix",
        ),
        ({"storage": MemorySessionStorage(), "redis_client": object()}, "can't be combined"),
        ({"storage": MemorySessionStorage(), "backend": "memory"}, "can't be combined"),
        ({"storage": MemorySessionStorage()}, "needs a csrf_storage"),
        ({"csrf_storage": MemorySessionStorage()}, "only used together with storage"),
        (
            {
                "storage": MemorySessionStorage(),
                "csrf_storage": MemorySessionStorage(),
                "storage_prefix": "x:",
            },
            "carries its own key prefix",
        ),
    ],
    ids=[
        "same-cookies",
        "same-prefixes",
        "storage-and-redis",
        "storage-and-backend",
        "no-csrf-store",
        "csrf-store-alone",
        "storage-and-prefix",
    ],
)
def test_a_contradictory_configuration_is_refused(options: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        SessionTransport(**options)


def test_a_store_without_csrf_needs_no_csrf_store() -> None:
    SessionTransport(storage=MemorySessionStorage(), csrf=False)


async def _lock_out(client: httpx.AsyncClient) -> None:
    for _ in range(LOCKOUT.max_attempts):
        await client.post("/login", data={"username": "both", "password": "wrong"})
    assert (await _login(client)).status_code == 429


def _limited_app(
    get_session: Any, UserModel: Any, prefix: str | None, **storage: Any
) -> tuple[CRUDAuth, FastAPI]:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        lockout=LOCKOUT,
        rate_limit_prefix=prefix,
        **storage,
    )
    app = FastAPI()
    app.include_router(auth.router)
    return auth, app


@pytest.mark.parametrize("backend", ["redis", "database"])
@pytest.mark.parametrize(
    ("admin_prefix", "locked"), [(None, True), ("admin:rl:", False)], ids=["shared", "own"]
)
async def test_a_lockout_in_one_app_does_not_lock_the_other_out_with_its_own_prefix(
    get_session: Any,
    UserModel: Any,
    sessionmaker: Any,
    backend: str,
    admin_prefix: str | None,
    locked: bool,
) -> None:
    """Failures in the main app lock the username out there; the admin, sharing the store, is
    locked out too unless its counters have their own prefix."""
    redis = fakeredis.aioredis.FakeRedis()
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    database = DatabaseStore(engine)
    await database.create_tables()
    shared: dict[str, Any] = (
        {"redis_client": redis} if backend == "redis" else {"database_store": database}
    )
    main, main_app = _limited_app(get_session, UserModel, None, **shared)
    admin, admin_app = _limited_app(get_session, UserModel, admin_prefix, **shared)
    await main.initialize()
    await admin.initialize()
    await _user(sessionmaker, UserModel)

    async with _client(main_app) as browser:
        await _lock_out(browser)
    async with _client(admin_app) as browser:
        status = (await _login(browser)).status_code
    await main.shutdown()
    await admin.shutdown()
    await redis.aclose()
    await engine.dispose()

    assert status == (429 if locked else 200)


def test_redis_rate_limiter_takes_a_prefix() -> None:
    limiter = redis_rate_limiter(client=fakeredis.aioredis.FakeRedis(), prefix="admin:rl:")

    assert isinstance(limiter, RedisBackend)
    assert limiter.prefix == "admin:rl:"


def test_rate_limit_prefix_is_refused_beside_a_rate_limiter_of_your_own(
    get_session: Any, UserModel: Any
) -> None:
    with pytest.raises(ValueError, match="rate_limit_prefix"):
        CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY=SECRET,
            rate_limiter=MemoryRateLimiterBackend(),
            rate_limit_prefix="admin:rl:",
        )
