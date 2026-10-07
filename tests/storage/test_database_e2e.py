"""Two workers, one database: a CRUDAuth app whose every store lives in the database.

Each "worker" is its own CRUDAuth with its own DatabaseStore on the same database, as
two processes would be. What one does, the other sees: the session it created, the
lockout pressure it counted, the sign-out it ordered.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from crudauth import AuthUserMixin, CookieConfig, CRUDAuth, DatabaseStore, SessionTransport
from crudauth.ratelimit.backends.database import DatabaseRateLimiterBackend
from crudauth.repository import UserRepository
from crudauth.storage import DatabaseSessionStorage
from crudauth.utils import get_password_hash
from tests.storage.conftest import DIALECTS

SECRET = "test-secret-key-0123456789-0123456789"
PASSWORD = "two-workers-pass-1"


class Base(DeclarativeBase):
    pass


class User(Base, AuthUserMixin):
    __tablename__ = "e2e_users"


Worker = tuple[CRUDAuth, FastAPI]


@pytest_asyncio.fixture(params=DIALECTS)
async def workers(
    request: pytest.FixtureRequest, engine_for: Any
) -> AsyncIterator[tuple[Worker, Worker, Any]]:
    engine, _ = await engine_for(request.param)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def get_session() -> AsyncIterator[AsyncSession]:
        async with sessions() as session:
            yield session

    def worker() -> Worker:
        auth = CRUDAuth(
            session=get_session,
            user_model=User,
            SECRET_KEY=SECRET,
            transports=[SessionTransport(cookies=CookieConfig(secure=False))],
            database_store=DatabaseStore(sessions),
        )
        app = FastAPI()
        app.include_router(auth.router)
        return auth, app

    first, second = worker(), worker()
    for auth, _ in (first, second):
        await auth.initialize()
    async with sessions() as db:
        await UserRepository(User).create(
            db,
            {
                "email": "w@x.com",
                "username": "worker",
                "hashed_password": get_password_hash(PASSWORD),
                "email_verified": True,
            },
        )
    yield first, second, sessions
    for auth, _ in (first, second):
        await auth.shutdown()
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def test_every_store_is_on_the_database(workers: tuple[Worker, Worker, Any]) -> None:
    (auth, _), _, _ = workers

    assert isinstance(auth.runtime.rate_limiter, DatabaseRateLimiterBackend)
    assert isinstance(auth.sessions.storage, DatabaseSessionStorage)
    assert auth._session_transport is not None and auth._session_transport.backend == "database"
    assert all(isinstance(store, DatabaseSessionStorage) for _, store in auth._stores)


async def test_a_session_made_on_one_worker_is_good_on_the_other(
    workers: tuple[Worker, Worker, Any],
) -> None:
    (_, first_app), (_, second_app), _ = workers

    async with _client(first_app) as on_first:
        signed_in = await on_first.post("/login", data={"username": "worker", "password": PASSWORD})
        cookies = dict(on_first.cookies)
    async with _client(second_app) as on_second:
        on_second.cookies.update(cookies)
        me = await on_second.get("/me")

    assert signed_in.status_code == 200
    assert me.status_code == 200
    assert me.json()["username"] == "worker"


async def test_lockout_counts_failures_from_both_workers(
    workers: tuple[Worker, Worker, Any],
) -> None:
    (first_auth, first_app), (_, second_app), _ = workers
    allowed = first_auth.runtime.lockout.max_attempts if first_auth.runtime.lockout else 5

    async with _client(first_app) as on_first, _client(second_app) as on_second:
        for attempt in range(allowed):
            client = on_first if attempt % 2 == 0 else on_second
            refused = await client.post(
                "/login", data={"username": "worker", "password": "wrong-pass-123"}
            )
            assert refused.status_code == 401
        locked = await on_second.post("/login", data={"username": "worker", "password": PASSWORD})

    assert locked.status_code == 429


async def test_signing_out_everywhere_on_one_worker_ends_sessions_made_on_the_other(
    workers: tuple[Worker, Worker, Any],
) -> None:
    (first_auth, first_app), (second_auth, second_app), _ = workers

    async with _client(first_app) as laptop, _client(second_app) as phone:
        await laptop.post("/login", data={"username": "worker", "password": PASSWORD})
        await phone.post("/login", data={"username": "worker", "password": PASSWORD})
        user_id = (await laptop.get("/me")).json()["user_id"]

        revoked = await second_auth.sessions.revoke_all(user_id)
        laptop_me = await laptop.get("/me")
        phone_me = await phone.get("/me")

    assert revoked == 2
    assert (laptop_me.status_code, phone_me.status_code) == (401, 401)
    assert await first_auth.sessions.list_for_user(user_id) == []


class TestWiring:
    @staticmethod
    def _sessions() -> Any:
        from sqlalchemy.ext.asyncio import create_async_engine

        return async_sessionmaker(
            create_async_engine("sqlite+aiosqlite://"), expire_on_commit=False
        )

    def _auth(self, **options: Any) -> CRUDAuth:
        async def get_session() -> AsyncIterator[AsyncSession]:  # pragma: no cover
            yield None  # type: ignore[misc]

        return CRUDAuth(session=get_session, user_model=User, SECRET_KEY=SECRET, **options)

    def test_a_database_store_cannot_be_combined_with_redis(self) -> None:
        with pytest.raises(ValueError, match="database_store can't be combined"):
            self._auth(
                database_store=DatabaseStore(self._sessions()), redis_url="redis://localhost:6379/0"
            )

    def test_backend_database_needs_a_database_store(self) -> None:
        with pytest.raises(ValueError, match="needs CRUDAuth\\(database_store=...\\)"):
            self._auth(transports=[SessionTransport(backend="database")])

    def test_backend_database_cannot_take_a_redis_client(self) -> None:
        with pytest.raises(ValueError, match="can't be combined with redis_url or redis_client"):
            SessionTransport(backend="database", redis_client=object())

    def test_the_factory_needs_a_store_for_the_database_backend(self) -> None:
        from crudauth.storage import get_session_storage

        with pytest.raises(ValueError, match="needs a DatabaseStore"):
            get_session_storage("database")

    def test_an_unknown_backend_fails_loudly(self) -> None:
        from crudauth.storage import get_session_storage

        with pytest.raises(ValueError, match="Unknown session backend: 'memcached'"):
            get_session_storage("memcached")

    def test_a_memory_transport_beside_a_database_store_keeps_its_own_backend(self) -> None:
        auth = self._auth(
            database_store=DatabaseStore(self._sessions()),
            transports=[SessionTransport(backend="memory")],
        )

        assert auth._session_transport is not None and auth._session_transport.backend == "memory"
        assert isinstance(auth.runtime.rate_limiter, DatabaseRateLimiterBackend)

    def test_no_memory_warning_with_a_database_store(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING", logger="crudauth"):
            self._auth(database_store=DatabaseStore(self._sessions()))

        assert "in-memory backend" not in caplog.text


def test_a_supplied_session_store_works_beside_the_email_and_oauth_stores() -> None:
    """0.8.0 refused this: building a token store asked for an unknown 'custom' backend."""
    from crudauth import EmailConfig, EmailSender, OAuthCredentials
    from crudauth.storage import MemorySessionStorage

    class Quiet(EmailSender):
        async def send(self, **kwargs: Any) -> None:  # pragma: no cover
            return None

    async def get_session() -> AsyncIterator[AsyncSession]:  # pragma: no cover
        yield None  # type: ignore[misc]

    auth = CRUDAuth(
        session=get_session,
        user_model=User,
        SECRET_KEY=SECRET,
        transports=[
            SessionTransport(storage=MemorySessionStorage(), csrf_storage=MemorySessionStorage())
        ],
        email=EmailConfig(sender=Quiet(), frontend_url="https://app.example.com"),
        oauth={"google": OAuthCredentials(client_id="id", client_secret="secret")},
        redirect_base_url="https://app.example.com",
        warn_on_memory_backend=False,
    )

    assert auth._stores
    assert all(isinstance(store, MemorySessionStorage) for _, store in auth._stores)
