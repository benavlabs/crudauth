"""What a session store holds, how long a session may live, and what a second login does to the first."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import fakeredis.aioredis
import httpx
from fastapi import FastAPI
from starlette.requests import Request

from crudauth import CookieConfig, CRUDAuth, SessionTransport
from crudauth.repository import UserRepository
from crudauth.transports.session.schemas import SessionData
from crudauth.utils import get_password_hash

SECRET = "test-secret-key-0123456789-0123456789"
PASSWORD = "at-rest-pass-123"


def _auth(get_session, UserModel, **transport_options) -> CRUDAuth:
    return CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False), **transport_options)],
    )


def _app(auth: CRUDAuth) -> FastAPI:
    app = FastAPI()
    app.include_router(auth.router)
    return app


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def _request() -> Request:
    return Request({"type": "http", "headers": [], "client": ("127.0.0.1", 1234)})


async def _user(sessionmaker, UserModel) -> None:
    async with sessionmaker() as db:
        await UserRepository(UserModel).create(
            db,
            {
                "email": "rest@x.com",
                "username": "rest",
                "hashed_password": get_password_hash(PASSWORD),
                "email_verified": True,
            },
        )


async def test_the_store_holds_neither_the_session_id_nor_the_csrf_token(
    get_session, UserModel, sessionmaker
) -> None:
    """Read access to Redis must not be enough to sign in."""
    redis = fakeredis.aioredis.FakeRedis()
    auth = _auth(get_session, UserModel, redis_client=redis)
    await auth.initialize()
    await _user(sessionmaker, UserModel)

    async with _client(_app(auth)) as browser:
        signed_in = await browser.post("/login", data={"username": "rest", "password": PASSWORD})
        session_id = browser.cookies.get("session_id")
        csrf_token = browser.cookies.get("csrf_token")
        me = await browser.get("/me")
    keys = [key if isinstance(key, bytes) else key.encode() for key in await redis.keys("*")]
    values = [await redis.dump(key) or b"" for key in keys]
    dumped = b"".join(keys + values)
    await auth.shutdown()
    await redis.aclose()

    assert (signed_in.status_code, me.status_code) == (200, 200)
    assert session_id and csrf_token
    assert session_id.encode() not in dumped
    assert csrf_token.encode() not in dumped


async def test_another_secret_reads_none_of_the_sessions(get_session, UserModel) -> None:
    """The key is an HMAC under SECRET_KEY, so rotating the key signs everyone out."""
    redis = fakeredis.aioredis.FakeRedis()
    first = _auth(get_session, UserModel, redis_client=redis)
    session_id, _ = await first.sessions.create_session(_request(), user_id=3)
    rotated = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="another-secret-key-0123456789-0123456789",
        transports=[SessionTransport(redis_client=redis, cookies=CookieConfig(secure=False))],
    )

    assert await first.sessions.validate_session(session_id) is not None
    assert await rotated.sessions.validate_session(session_id) is None
    await redis.aclose()


async def test_a_session_past_its_absolute_lifetime_ends_however_active_it_is(
    get_session, UserModel
) -> None:
    auth = _auth(get_session, UserModel, absolute_timeout_hours=12)
    manager = auth.sessions
    session_id, _ = await manager.create_session(_request(), user_id=4)

    def signed_in_long_ago(session: SessionData) -> None:
        session.created_at = datetime.now(timezone.utc) - timedelta(hours=13)

    await manager.modify_session(session_id, signed_in_long_ago)

    assert await manager.validate_session(session_id) is None
    assert await manager.get_session(session_id) is None


async def test_a_session_inside_its_absolute_lifetime_is_kept(get_session, UserModel) -> None:
    auth = _auth(get_session, UserModel, absolute_timeout_hours=12)
    manager = auth.sessions
    session_id, _ = await manager.create_session(_request(), user_id=4)

    def signed_in_this_morning(session: SessionData) -> None:
        session.created_at = datetime.now(timezone.utc) - timedelta(hours=11)

    await manager.modify_session(session_id, signed_in_this_morning)

    assert await manager.validate_session(session_id) is not None


async def test_without_an_absolute_lifetime_an_old_active_session_is_kept(
    get_session, UserModel
) -> None:
    auth = _auth(get_session, UserModel)
    manager = auth.sessions
    session_id, _ = await manager.create_session(_request(), user_id=4)

    def signed_in_last_year(session: SessionData) -> None:
        session.created_at = datetime.now(timezone.utc) - timedelta(days=365)

    await manager.modify_session(session_id, signed_in_last_year)

    assert await manager.validate_session(session_id) is not None


async def test_signing_in_again_ends_the_session_the_browser_presented(
    get_session, UserModel, sessionmaker
) -> None:
    """The old cookie is overwritten in the browser; it must not stay usable for whoever copied it."""
    auth = _auth(get_session, UserModel)
    await auth.initialize()
    await _user(sessionmaker, UserModel)

    async with _client(_app(auth)) as browser:
        await browser.post("/login", data={"username": "rest", "password": PASSWORD})
        first = browser.cookies.get("session_id")
        await browser.post("/login", data={"username": "rest", "password": PASSWORD})
        second = browser.cookies.get("session_id")
        listed = await auth.sessions.list_for_user(1)
    await auth.shutdown()

    assert first and second and first != second
    assert await auth.sessions.get_session(first) is None
    assert await auth.sessions.get_session(second) is not None
    assert len(listed) == 1


async def test_signing_in_elsewhere_keeps_other_browsers_signed_in(
    get_session, UserModel, sessionmaker
) -> None:
    auth = _auth(get_session, UserModel)
    await auth.initialize()
    await _user(sessionmaker, UserModel)
    app = _app(auth)

    async with _client(app) as laptop, _client(app) as phone:
        await laptop.post("/login", data={"username": "rest", "password": PASSWORD})
        await phone.post("/login", data={"username": "rest", "password": PASSWORD})
        laptop_me = await laptop.get("/me")
        phone_me = await phone.get("/me")
    await auth.shutdown()

    assert (laptop_me.status_code, phone_me.status_code) == (200, 200)
