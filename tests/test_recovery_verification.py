"""Recovery-verification generalization: "verified" means proof of control of the
contract's recovery factor; email is the special case. Same proof machinery (signed
one-time token returned over the channel) for any factor - only the delivery channel
and the verified column change. The flag must stay as unsettable as email_verified."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
from fastapi import Depends, FastAPI
from sqlalchemy import String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from crudauth import (
    AuthUserMixin,
    CookieConfig,
    CRUDAuth,
    DeliveryChannel,
    DeliveryIntent,
    IdentityConfig,
    Principal,
    SessionTransport,
    make_auth_identity,
)
from crudauth.exceptions import BadRequestException
from crudauth.repository import UserRepository
from crudauth.utils import get_password_hash

SECRET = "test-secret-key-0123456789-0123456789"

_PhoneMixin: Any = make_auth_identity(identifiers=["username"], recovery="phone", oauth=False)


class _PhoneBase(DeclarativeBase):
    pass


class PhoneUser(_PhoneBase, _PhoneMixin):
    __tablename__ = "rv_phone_users"
    phone: Mapped[str | None] = mapped_column(String(32), unique=True, default=None)


class RecordingChannel(DeliveryChannel):
    def __init__(self) -> None:
        self.intents: list[DeliveryIntent] = []

    async def deliver(self, intent: DeliveryIntent, db) -> None:
        self.intents.append(intent)


# --- mixin factory: {factor}_verified -------------------------------------


def test_factory_emits_phone_verified() -> None:
    assert "phone_verified" in {c.name for c in PhoneUser.__table__.columns}


def test_factory_does_not_double_emit_email_verified() -> None:
    class B(DeclarativeBase):
        pass

    class U(B, AuthUserMixin):
        __tablename__ = "rv_default_users"

    names = [c.name for c in U.__table__.columns]
    assert names.count("email_verified") == 1


def test_factory_anonymous_emits_no_extra_verified_flag() -> None:
    anon: Any = make_auth_identity(identifiers=["username"], recovery=None, oauth=False)

    class B(DeclarativeBase):
        pass

    class U(B, anon):
        __tablename__ = "rv_anon_users"

    extra = [
        c.name
        for c in U.__table__.columns
        if c.name.endswith("_verified") and c.name != "email_verified"
    ]
    assert extra == []


# --- recovery_verified reads the right column per factor -------------------


def test_recovery_verified_reads_right_column_per_factor(UserModel) -> None:
    email_repo = UserRepository(UserModel)  # default recovery="email"
    u = UserModel()
    u.email_verified = True
    assert email_repo.recovery_verified(u) is True
    u.email_verified = False
    assert email_repo.recovery_verified(u) is False

    phone_repo = UserRepository(PhoneUser, recovery="phone")
    p = PhoneUser()
    p.phone_verified = True
    assert phone_repo.recovery_verified(p) is True
    p.phone_verified = False
    assert phone_repo.recovery_verified(p) is False

    none_repo = UserRepository(PhoneUser, recovery=None)
    p.phone_verified = True
    assert none_repo.recovery_verified(p) is False  # no recovery factor -> never verified


def test_email_recovery_equals_email_verified(UserModel) -> None:
    # email is the special case: recovery_verified reads email_verified for an email app.
    repo = UserRepository(UserModel)
    u = UserModel()
    u.email_verified = True
    assert repo.recovery_verified(u) is True and repo.email_verified(u) is True


# --- the flag is as unsettable as email_verified (three write paths) -------


def test_factor_verified_unsettable_via_register_and_provisioning() -> None:
    # (1) register: even opted into register_extra_fields, the verified flag is gated
    reg_repo = UserRepository(PhoneUser, register_extra_fields={"phone_verified"}, recovery="phone")
    assert "phone_verified" not in reg_repo.filter_registration_data(
        {"username": "u", "phone_verified": True}
    )
    # (2) new_user_fields callback flows through filter_provisioning_data -> dropped
    prov_repo = UserRepository(PhoneUser, recovery="phone")
    assert prov_repo.filter_provisioning_data({"phone": "1", "phone_verified": True}) == {
        "phone": "1"
    }


def test_factor_verified_unsettable_via_new_user_defaults(get_session) -> None:
    # (3) new_user_defaults is gated at construction
    auth = CRUDAuth(
        session=get_session,
        user_model=PhoneUser,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        identity=IdentityConfig(login=["username"], recovery="phone"),
        new_user_defaults={"phone_verified": True, "phone": "x"},
    )
    assert "phone_verified" not in auth._new_user_defaults
    assert auth._new_user_defaults == {"phone": "x"}


# --- the gate flips to the recovery factor --------------------------------


def test_verified_gate_requires_recovery_factor(get_session, UserModel) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        identity=IdentityConfig(login=["email", "username"], recovery=None),
    )
    with pytest.raises(ValueError, match="recovery factor"):
        auth.current_user(verified=True)


# --- the proof: phone verify is the same machinery, re-pointed ------------


@asynccontextmanager
async def _phone_app() -> AsyncGenerator[tuple, None]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(_PhoneBase.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def get_session() -> AsyncGenerator[AsyncSession, None]:
        async with maker() as s:
            yield s

    channel = RecordingChannel()
    auth = CRUDAuth(
        session=get_session,
        user_model=PhoneUser,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        identity=IdentityConfig(login=["username"], recovery="phone"),
        channels=[channel],
    )
    app = FastAPI()
    app.include_router(auth.router)

    @app.get("/secret")
    async def secret(_: Principal = Depends(auth.current_user(verified=True))):
        return {"ok": True}

    await auth.initialize()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            yield auth, client, maker, channel
    finally:
        await auth.shutdown()
        await engine.dispose()


async def test_phone_verify_delivers_to_phone_and_gates_on_it() -> None:
    async with _phone_app() as (auth, client, maker, channel):
        repo = auth.repo
        async with maker() as db:
            await repo.create(
                db, {"username": "neo", "phone": "555", "hashed_password": get_password_hash("pw")}
            )
        await client.post("/login", data={"username": "neo", "password": "pw"})
        assert (await client.get("/secret")).status_code == 403  # not verified yet

        async with maker() as db:
            await auth._email_service.request_recovery_verification(db, "555")
        intent = channel.intents[-1]
        assert intent.recipient == "555"  # delivered to the PHONE, not an email
        # factor-neutral kind for a non-email factor (not the email-named "verify_email")
        assert intent.kind == "verify_recovery" and intent.token is not None

        async with maker() as db:
            await auth._email_service.confirm_recovery_verification(db, intent.token)
        assert (await client.get("/secret")).status_code == 200  # now verified


async def test_phone_reset_delivers_to_the_phone() -> None:
    # password reset re-points to the recovery factor too, not just verify: the
    # reset token is delivered to the phone, the same generalization as verify.
    async with _phone_app() as (auth, _client, maker, channel):
        repo = auth.repo
        async with maker() as db:
            await repo.create(
                db,
                {"username": "morph", "phone": "999", "hashed_password": get_password_hash("pw")},
            )
        async with maker() as db:
            await auth._email_service.request_password_reset(db, "999")
        intent = channel.intents[-1]
        assert intent.recipient == "999"  # delivered to the phone, not an email
        assert intent.kind == "reset_password" and intent.token is not None


async def test_phone_verify_requires_the_delivered_token() -> None:
    async with _phone_app() as (auth, _client, maker, channel):
        repo = auth.repo
        async with maker() as db:
            await repo.create(
                db,
                {"username": "trin", "phone": "777", "hashed_password": get_password_hash("pw")},
            )
        async with maker() as db:
            await auth._email_service.request_recovery_verification(db, "777")
        token = channel.intents[-1].token
        assert token is not None

        async with maker() as db:
            with pytest.raises(BadRequestException):
                await auth._email_service.confirm_recovery_verification(db, "not-a-token")
            assert repo.recovery_verified(await repo.get_by_field(db, "phone", "777")) is False

        async with maker() as db:
            await auth._email_service.confirm_recovery_verification(db, token)
            assert repo.recovery_verified(await repo.get_by_field(db, "phone", "777")) is True

        async with maker() as db:
            with pytest.raises(BadRequestException):
                await auth._email_service.confirm_recovery_verification(
                    db, token
                )  # replay rejected
            assert repo.recovery_verified(await repo.get_by_field(db, "phone", "777")) is True
