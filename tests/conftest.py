"""Shared fixtures: an in-memory SQLite app wired with crudauth."""

from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest_asyncio
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
