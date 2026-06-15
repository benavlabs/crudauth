"""Repository behavior under column_map: email canonicalization + alias gating."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from crudauth.repository import UserRepository


class Base(DeclarativeBase):
    pass


class Account(Base):
    __tablename__ = "accounts"

    account_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    email_address: Mapped[str] = mapped_column(unique=True)
    username: Mapped[str] = mapped_column(unique=True)
    pw_hash: Mapped[str] = mapped_column()
    is_admin: Mapped[bool] = mapped_column(default=False)


COLUMN_MAP = {
    "id": "account_id",
    "email": "email_address",
    "hashed_password": "pw_hash",
    "is_superuser": "is_admin",
}


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with maker() as s:
        yield s
    await engine.dispose()


# --- create() canonicalizes the *resolved* email column ----------------------
async def test_create_canonicalizes_email_under_column_map(session) -> None:
    repo = UserRepository(Account, column_map=COLUMN_MAP)
    user = await repo.create(
        session,
        {"email": "  Foo@X.COM ", "username": "foo", "hashed_password": "h"},
    )
    # stored normalized despite email being mapped to `email_address`
    assert user.email_address == "foo@x.com"
    # and the OAuth-link / password-login lookup finds it case-insensitively
    found = await repo.get_by_email(session, "FOO@x.com")
    assert found is not None
    assert repo.user_id(found) == repo.user_id(user)


# --- a column_map alias of a gated field is still dropped at registration -----
def test_filter_registration_data_closes_alias_hole() -> None:
    repo = UserRepository(Account, column_map=COLUMN_MAP, register_extra_fields={"full_name"})
    # `is_admin` is the mapped column name of the gated logical `is_superuser`
    out = repo.filter_registration_data(
        {"email": "a@x.com", "username": "a", "is_admin": True, "full_name": "ok"}
    )
    assert "is_admin" not in out  # gated by resolved column name, even if opted in
    assert out == {"email": "a@x.com", "username": "a", "full_name": "ok"}


def test_gated_register_fields_flags_alias() -> None:
    repo = UserRepository(Account, column_map=COLUMN_MAP)
    # a register schema declaring the mapped name is flagged at startup
    assert repo.gated_register_fields(["email", "username", "is_admin"]) == {"is_admin"}


async def test_increment_token_version_noop_without_column(session) -> None:
    # Account has no token_version column → epoch revocation is a graceful no-op.
    repo = UserRepository(Account, column_map=COLUMN_MAP)
    acct = await repo.create(session, {"email": "a@x.com", "username": "a", "hashed_password": "h"})
    assert repo.token_version(acct) == 0
    await repo.increment_token_version(session, acct)  # no column → no error, no change
    assert repo.token_version(acct) == 0


# --- token_version on a model that *has* the column (conftest UserModel) ------
async def test_token_version_increments(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        user = await repo.create(
            db, {"email": "tv@x.com", "username": "tv", "hashed_password": "h"}
        )
        assert repo.token_version(user) == 0
        await repo.increment_token_version(db, user)
        assert repo.token_version(user) == 1


def test_column_map_translation(UserModel) -> None:
    repo = UserRepository(UserModel, column_map={"email": "email", "id": "id"})
    assert repo.col("email") == "email"
    repo2 = UserRepository(UserModel, column_map={"hashed_password": "email"})
    assert repo2.col("hashed_password") == "email"
