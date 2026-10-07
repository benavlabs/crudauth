"""Shared fixtures: an in-memory SQLite app wired with crudauth."""

from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest_asyncio
from fastapi import APIRouter, FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from crudauth.models import AuthUserMixin


class Base(DeclarativeBase):
    pass


class User(Base, AuthUserMixin):
    """Test user model with two app-defined columns outside crudauth's logical
    contract: ``full_name`` (opt-in extra) and ``role`` (privileged, used to
    exercise registration mass-assignment gating)."""

    __tablename__ = "users"

    full_name: Mapped[str | None] = mapped_column(default=None)
    role: Mapped[str] = mapped_column(default="user")
    # Per-provider id columns for the custom OAuth providers exercised in tests
    # (built-ins google_id/github_id come from AuthUserMixin).
    stub_id: Mapped[str | None] = mapped_column(default=None)
    redir_id: Mapped[str | None] = mapped_column(default=None)
    oidc_id: Mapped[str | None] = mapped_column(default=None)


@pytest_asyncio.fixture
async def engine():
    eng = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def sessionmaker(engine):
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


@pytest_asyncio.fixture
async def get_session(sessionmaker):
    async def _get_session() -> AsyncGenerator[AsyncSession, None]:
        async with sessionmaker() as session:
            yield session

    return _get_session


@pytest_asyncio.fixture
def UserModel():
    return User


def mounted_paths(router: APIRouter) -> set[str]:
    """Every path ``router`` serves once mounted, read from the app's OpenAPI schema.

    ``router.routes`` is flat on older FastAPI and holds nested routers on newer ones,
    so a path check against it can pass with nothing mounted; the schema lists them all.
    """
    app = FastAPI()
    app.include_router(router)
    return set(app.openapi()["paths"])
