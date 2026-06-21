"""End-to-end flows against a real PostgreSQL (testcontainers).

These are the before/after behavior anchor for the toolbox refactor: full user
journeys (register, login, token, refresh, change-password, recovery, device
management) driven over HTTP against Postgres - which also catches dialect issues
SQLite hides, e.g. coercing a token's string ``sub`` to an integer primary key on
a strict backend.

The suite skips automatically when Docker (and testcontainers) isn't available.
"""

from __future__ import annotations

import os

os.environ.setdefault("TESTCONTAINERS_RYUK_DISABLED", "true")

from collections.abc import AsyncGenerator  # noqa: E402
from typing import Any  # noqa: E402

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column  # noqa: E402

from crudauth import (  # noqa: E402
    AuthUserMixin,
    BearerTransport,
    CookieConfig,
    CRUDAuth,
    DeliveryChannel,
    DeliveryIntent,
    SessionTransport,
)

try:
    from testcontainers.core.docker_client import DockerClient  # type: ignore[import-untyped]
    from testcontainers.postgres import PostgresContainer  # type: ignore[import-untyped]

    _HAS_TESTCONTAINERS = True
except ImportError:  # pragma: no cover - exercised only without the dep installed
    _HAS_TESTCONTAINERS = False

SECRET = "test-secret-key-0123456789-0123456789"


class Base(DeclarativeBase):
    pass


class User(Base, AuthUserMixin):
    """Default identity (email + username), plus an opt-in extra (``full_name``)
    and a privileged column (``role``) to exercise registration gating."""

    __tablename__ = "users"

    full_name: Mapped[str | None] = mapped_column(default=None)
    role: Mapped[str] = mapped_column(default="user")


class RecordingChannel(DeliveryChannel):
    """Captures delivery intents so a test can read the recovery token."""

    def __init__(self) -> None:
        self.intents: list[DeliveryIntent] = []

    async def deliver(self, intent: DeliveryIntent, db: Any) -> None:
        self.intents.append(intent)


def build_app(
    get_session: Any, channel: DeliveryChannel, **transport_kw: Any
) -> tuple[FastAPI, CRUDAuth]:
    """Build a full session + bearer + email-recovery app (management routes on)."""
    auth = CRUDAuth(
        session=get_session,
        user_model=User,
        SECRET_KEY=SECRET,
        transports=[
            SessionTransport(
                cookies=CookieConfig(secure=False), management_routes=True, **transport_kw
            ),
            BearerTransport(
                refresh="body"
            ),  # body token: deterministic over http (no secure cookie)
        ],
        channels=[channel],
        register_extra_fields={"full_name"},
    )
    app = FastAPI()
    app.include_router(auth.router)
    return app, auth


def _docker_running() -> bool:
    if not _HAS_TESTCONTAINERS:
        return False
    try:
        DockerClient()
        return True
    except Exception:
        return False


@pytest_asyncio.fixture(scope="session")
async def pg_url() -> AsyncGenerator[str, None]:
    if not _docker_running():
        pytest.skip("Docker + testcontainers required for the e2e suite")
    with PostgresContainer("postgres:16-alpine", driver="asyncpg") as pg:
        yield pg.get_connection_url()


@pytest_asyncio.fixture
async def pg_engine(pg_url: str):
    engine = create_async_engine(pg_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def maker(pg_engine: Any) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(pg_engine, expire_on_commit=False, class_=AsyncSession)


@pytest_asyncio.fixture
async def get_session(maker: async_sessionmaker[AsyncSession]) -> Any:
    async def _get_session() -> AsyncGenerator[AsyncSession, None]:
        async with maker() as session:
            yield session

    return _get_session


@pytest_asyncio.fixture
def app_factory(get_session: Any) -> Any:
    """Return ``build(**transport_kw) -> (app, auth, channel)`` wired to Postgres."""

    def _factory(**transport_kw: Any) -> tuple[FastAPI, CRUDAuth, RecordingChannel]:
        channel = RecordingChannel()
        app, auth = build_app(get_session, channel, **transport_kw)
        return app, auth, channel

    return _factory


@pytest_asyncio.fixture
async def app_ctx(
    app_factory: Any, maker: async_sessionmaker[AsyncSession]
) -> AsyncGenerator[
    tuple[CRUDAuth, httpx.AsyncClient, async_sessionmaker[AsyncSession], RecordingChannel], None
]:
    app, auth, channel = app_factory()
    await auth.initialize()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            yield auth, client, maker, channel
    finally:
        await auth.shutdown()
