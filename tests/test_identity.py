"""The identity contract: model-as-truth shape, fail-closed construction validation,
contract-driven login resolution, email-optional register, recovery-router gating."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from pydantic import BaseModel
from sqlalchemy import String, UniqueConstraint
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from crudauth import (
    AuthUserMixin,
    CookieConfig,
    CRUDAuth,
    EmailConfig,
    EmailSender,
    IdentityConfig,
    SessionTransport,
    make_auth_identity,
)
from crudauth.repository import UserRepository
from crudauth.utils import get_password_hash

SECRET = "test-secret-key-0123456789-0123456789"


class _Sender(EmailSender):
    async def send(
        self, *, to, subject, body, kind
    ) -> None:  # pragma: no cover - never sent in these tests
        pass


# --- model shapes (each its own metadata) ---------------------------------


_AnonMixin: Any = make_auth_identity(identifiers=["username"], recovery=None, oauth=False)
_PhoneMixin: Any = make_auth_identity(identifiers=["username"], recovery="phone", oauth=False)
_PlainMixin: Any = make_auth_identity(identifiers=["username"], recovery=None, oauth=False)
_RecoveryEmailMixin: Any = make_auth_identity(
    identifiers=["username"], recovery="email", oauth=False
)


class _ConstraintBase(DeclarativeBase):
    pass


class ConstraintUser(_ConstraintBase, _PlainMixin):
    __tablename__ = "constraint_users"
    phone: Mapped[str | None] = mapped_column(String(32), default=None)  # unique via table arg
    __table_args__ = (UniqueConstraint("phone"),)


class _AnonBase(DeclarativeBase):
    pass


class AnonUser(_AnonBase, _AnonMixin):
    __tablename__ = "anon_users"


class _PhoneBase(DeclarativeBase):
    pass


class PhoneUser(_PhoneBase, _PhoneMixin):
    __tablename__ = "phone_users"
    phone: Mapped[str | None] = mapped_column(String(32), unique=True, default=None)


class _PhoneBadBase(DeclarativeBase):
    pass


class PhoneBadUser(_PhoneBadBase, _PlainMixin):
    __tablename__ = "phone_bad_users"
    phone: Mapped[str | None] = mapped_column(String(32), default=None)  # NOT unique


class _CompBase(DeclarativeBase):
    pass


class CompUser(_CompBase, _PlainMixin):
    __tablename__ = "comp_users"
    email: Mapped[str | None] = mapped_column(
        String(320), default=None
    )  # unique only via composite
    tenant_id: Mapped[int] = mapped_column(default=0)
    __table_args__ = (UniqueConstraint("email", "tenant_id"),)


def _noop_session() -> None:  # stored by CRUDAuth, never called during construction
    return None


# --- mixin factory --------------------------------------------------------

EXPECTED_DEFAULT_COLUMNS = {
    "id": ("INTEGER", False, False, True),
    "email": ("VARCHAR(320)", False, True, False),
    "username": ("VARCHAR(64)", False, True, False),
    "hashed_password": ("VARCHAR(255)", False, False, False),
    "is_active": ("BOOLEAN", False, False, False),
    "is_superuser": ("BOOLEAN", False, False, False),
    "email_verified": ("BOOLEAN", False, False, False),
    "token_version": ("INTEGER", False, False, False),
    "oauth_provider": ("VARCHAR(32)", True, False, False),
    "google_id": ("VARCHAR(64)", True, True, False),
    "github_id": ("VARCHAR(64)", True, True, False),
    "oauth_created_at": ("DATETIME", True, False, False),
    "oauth_updated_at": ("DATETIME", True, False, False),
    "created_at": ("DATETIME", False, False, False),
    "updated_at": ("DATETIME", True, False, False),
}


def test_default_factory_is_column_identical_to_today() -> None:
    # The back-compat anchor: make_auth_identity() default must be the exact set of
    # columns the hand-written AuthUserMixin shipped, or every existing model's
    # schema silently shifts.
    class B(DeclarativeBase):
        pass

    class U(B, AuthUserMixin):
        __tablename__ = "anchor_users"

    cols = {
        c.name: (str(c.type), c.nullable, bool(c.unique), c.primary_key)
        for c in U.__table__.columns
    }
    assert cols == EXPECTED_DEFAULT_COLUMNS


def test_two_inheritors_get_independent_columns() -> None:
    # The one place the factory can differ from a hand-written mixin: two models
    # inheriting the same factory output must each get their own columns.
    class B(DeclarativeBase):
        pass

    class U(B, AuthUserMixin):
        __tablename__ = "ti_users"

    class A(B, AuthUserMixin):
        __tablename__ = "ti_admins"

    assert len(U.__table__.columns) == len(A.__table__.columns) == 15
    assert U.__table__.c.email is not A.__table__.c.email


def test_anonymous_shape_has_no_email_column() -> None:
    cols = {c.name for c in AnonUser.__table__.columns}
    assert "email" not in cols
    assert {"id", "username", "hashed_password"} <= cols


def test_recovery_only_email_is_nullable_and_unique() -> None:
    # email is the recovery spine but not a login field -> present, nullable, unique.
    class B(DeclarativeBase):
        pass

    class U(B, _RecoveryEmailMixin):
        __tablename__ = "rec_email_users"

    email_col = U.__table__.c.email
    assert email_col.nullable is True
    assert bool(email_col.unique) is True


def test_is_unique_column_detects_each_form() -> None:
    # The fail-closed primitive: column-level unique=True, single-column table-level
    # UniqueConstraint -> unique; a non-unique column and a composite-only field -> not.
    repo = UserRepository(ConstraintUser)
    assert repo.is_unique_column("username") is True  # column-level unique=True
    assert repo.is_unique_column("phone") is True  # single-column UniqueConstraint
    assert repo.is_unique_column("hashed_password") is False  # not unique
    assert UserRepository(CompUser).is_unique_column("email") is False  # composite-only


# --- construction validation (fail-closed) --------------------------------


def _build(model, **kwargs):
    return CRUDAuth(
        session=_noop_session,
        user_model=model,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        **kwargs,
    )


def test_login_field_must_be_a_unique_column() -> None:
    with pytest.raises(ValueError, match="login field 'phone'"):
        _build(PhoneBadUser, identity=IdentityConfig(login=["username", "phone"]))


def test_recovery_field_must_be_a_unique_column() -> None:
    with pytest.raises(ValueError, match="recovery field 'phone'"):
        _build(PhoneBadUser, identity=IdentityConfig(login=["username"], recovery="phone"))


def test_recovery_field_must_exist() -> None:
    with pytest.raises(ValueError, match="recovery field 'phone'"):
        _build(AnonUser, identity=IdentityConfig(login=["username"], recovery="phone"))


def test_composite_only_unique_field_raises() -> None:
    # email is unique only via a composite UniqueConstraint -> not a safe login key.
    with pytest.raises(ValueError, match="login field 'email'"):
        _build(CompUser, identity=IdentityConfig(login=["email"], recovery=None))


def test_oauth_requires_email_in_login() -> None:
    with pytest.raises(ValueError, match="OAuth requires 'email'"):
        _build(
            AnonUser,
            identity=IdentityConfig(login=["username"], recovery=None),
            oauth={"google": None},
        )


def test_email_config_requires_email_column() -> None:
    with pytest.raises(ValueError, match="requires an 'email' column"):
        _build(
            AnonUser,
            identity=IdentityConfig(login=["username"], recovery=None),
            email=EmailConfig(sender=_Sender(), frontend_url="https://app"),
        )


def test_verified_gate_requires_email_column() -> None:
    auth = _build(AnonUser, identity=IdentityConfig(login=["username"], recovery=None))
    with pytest.raises(ValueError, match="verified=True"):
        auth.current_user(verified=True)


def test_valid_phone_recovery_shape_constructs() -> None:
    # unique phone + username login + no email: a fully valid non-default shape.
    auth = _build(PhoneUser, identity=IdentityConfig(login=["username"], recovery="phone"))
    assert auth.identity.recovery == "phone"


# --- contract-driven login resolution (no @-heuristic) --------------------


async def test_login_resolves_by_configured_fields(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel)  # default login=["email","username"]
    async with sessionmaker() as db:
        await repo.create(
            db,
            {"email": "a@x.com", "username": "alice", "hashed_password": get_password_hash("pw")},
        )
    async with sessionmaker() as db:
        assert repo.user_id(await repo.resolve_login(db, "a@x.com")) is not None
        assert repo.user_id(await repo.resolve_login(db, "alice")) is not None


async def test_username_only_login_does_not_fall_through_to_email(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel, login_fields=["username"])
    async with sessionmaker() as db:
        await repo.create(
            db,
            {"email": "a@x.com", "username": "alice", "hashed_password": get_password_hash("pw")},
        )
    async with sessionmaker() as db:
        assert await repo.resolve_login(db, "a@x.com") is None  # email is NOT a login field
        assert await repo.resolve_login(db, "alice") is not None


async def test_username_login_is_case_sensitive_and_clean(sessionmaker, UserModel) -> None:
    # username is matched as-is (no canonicalization), so a wrong-case attempt simply
    # misses and returns None - a clean failed login, not an error (lockout then keys
    # on the raw value, consistent with the lookup).
    repo = UserRepository(UserModel, login_fields=["username"])
    async with sessionmaker() as db:
        await repo.create(
            db,
            {"email": "b@x.com", "username": "Alice", "hashed_password": get_password_hash("pw")},
        )
    async with sessionmaker() as db:
        assert await repo.resolve_login(db, "alice") is None  # wrong case misses cleanly
        assert await repo.resolve_login(db, "Alice") is not None


# --- email-optional register + recovery gating ----------------------------


@asynccontextmanager
async def _app(model, base, **kwargs) -> AsyncGenerator[tuple, None]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def get_session() -> AsyncGenerator[AsyncSession, None]:
        async with maker() as s:
            yield s

    auth = CRUDAuth(
        session=get_session,
        user_model=model,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        **kwargs,
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            yield auth, client, maker
    finally:
        await auth.shutdown()
        await engine.dispose()


class _AnonRegister(BaseModel):
    username: str
    password: str


async def test_register_anonymous_username_only() -> None:
    identity = IdentityConfig(login=["username"], recovery=None)
    async with _app(AnonUser, _AnonBase, identity=identity, register_schema=_AnonRegister) as ctx:
        _auth, client, maker = ctx
        r = await client.post("/register", json={"username": "neo", "password": "pw123456"})
        assert r.status_code == 200, r.text  # no email KeyError, no leak
        repo = UserRepository(AnonUser, login_fields=["username"])
        async with maker() as db:
            assert await repo.resolve_login(db, "neo") is not None


async def test_register_anonymous_duplicate_username_surfaces() -> None:
    identity = IdentityConfig(login=["username"], recovery=None)
    async with _app(AnonUser, _AnonBase, identity=identity, register_schema=_AnonRegister) as ctx:
        _auth, client, _maker = ctx
        await client.post("/register", json={"username": "dup", "password": "pw123456"})
        r = await client.post("/register", json={"username": "dup", "password": "pw123456"})
        assert r.status_code == 422
        assert "already taken" in r.text.lower()


async def test_recovery_none_omits_recovery_endpoints(get_session, UserModel) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        identity=IdentityConfig(login=["email", "username"], recovery=None),
        email=EmailConfig(sender=_Sender(), frontend_url="https://app"),
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        r = await client.post("/password/reset-request", json={"email": "a@x.com"})
        assert r.status_code == 404  # recovery router not mounted
    await auth.shutdown()


async def test_recovery_email_mounts_recovery_endpoints(get_session, UserModel) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        email=EmailConfig(sender=_Sender(), frontend_url="https://app"),
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        r = await client.post("/password/reset-request", json={"email": "a@x.com"})
        assert r.status_code == 200  # mounted, non-enumerating
    await auth.shutdown()
