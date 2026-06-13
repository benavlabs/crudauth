"""Registration field gating: a strict allowlist - only opted-in fields persist."""

from __future__ import annotations

import logging

import httpx
import pytest
from fastapi import FastAPI
from pydantic import BaseModel

from crudauth import CookieConfig, CRUDAuth, SessionTransport
from crudauth.repository import (
    REGISTRATION_ALLOWED_FIELDS,
    REGISTRATION_GATED_FIELDS,
    UserRepository,
)


# A schema a careless dev might copy-paste from their UserCreate, leaking privilege.
class DangerousRegister(BaseModel):
    email: str
    username: str
    password: str
    full_name: str | None = None
    role: str = "user"  # app-defined privileged column
    is_superuser: bool = False
    email_verified: bool = False


def test_allowlist_and_gated_sets_are_consistent() -> None:
    assert REGISTRATION_ALLOWED_FIELDS == {"email", "username"}
    # the gated set is everything privileged/state/identity - never user-settable
    assert {"is_superuser", "is_active", "email_verified", "hashed_password", "id"} <= (
        REGISTRATION_GATED_FIELDS
    )
    assert {"google_id", "github_id", "oauth_provider"} <= REGISTRATION_GATED_FIELDS
    # and the allowed fields are NOT in the gated set
    assert REGISTRATION_ALLOWED_FIELDS.isdisjoint(REGISTRATION_GATED_FIELDS)


def test_filter_allowlist_drops_unopted_and_privileged(UserModel) -> None:
    # No extras opted in: only email/username survive. Real app columns
    # (full_name, role) are dropped, as are all privileged logical fields.
    repo = UserRepository(UserModel)
    out = repo.filter_registration_data(
        {
            "email": "a@x.com",
            "username": "a",
            "full_name": "A",  # real column, NOT opted in -> dropped
            "role": "admin",  # app-defined privileged column -> dropped
            "is_superuser": True,  # gated
            "email_verified": True,  # gated
            "hashed_password": "x",  # gated
            "id": 99,  # gated
        }
    )
    assert out == {"email": "a@x.com", "username": "a"}


def test_filter_keeps_opted_in_extra(UserModel) -> None:
    repo = UserRepository(UserModel, register_extra_fields={"full_name"})
    out = repo.filter_registration_data(
        {"email": "a@x.com", "username": "a", "full_name": "A", "role": "admin"}
    )
    # only the opted-in column rides along; the un-opted role is still dropped
    assert out == {"email": "a@x.com", "username": "a", "full_name": "A"}


def test_gated_field_cannot_be_opted_in(UserModel) -> None:
    # Even if a developer mistakenly opts a privileged field in, it stays gated.
    repo = UserRepository(UserModel, register_extra_fields={"is_superuser"})
    out = repo.filter_registration_data({"email": "a@x.com", "username": "a", "is_superuser": True})
    assert "is_superuser" not in out


@pytest.fixture
async def client(get_session, UserModel):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        register_schema=DangerousRegister,
        register_extra_fields={"full_name"},  # opt in full_name, but NOT role
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c, auth
    await auth.shutdown()


async def test_privilege_escalation_is_inert(client, sessionmaker, UserModel) -> None:
    c, auth = client
    r = await c.post(
        "/register",
        json={
            "email": "evil@x.com",
            "username": "evil",
            "password": "pw123456",
            "full_name": "Evil",
            "role": "admin",
            "is_superuser": True,
            "email_verified": True,
        },
    )
    assert r.status_code == 200, r.text

    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "evil@x.com")
    assert user is not None
    # privileged logical fields dropped, un-opted app column (role) dropped,
    # opted-in column (full_name) kept
    assert user.is_superuser is False
    assert user.email_verified is False
    assert user.role == "user"  # NOT "admin" - the mass-assignment is closed
    assert user.full_name == "Evil"


async def test_app_column_not_settable_without_opt_in(get_session, UserModel, sessionmaker) -> None:
    # Same dangerous schema, but NO register_extra_fields at all: full_name and
    # role both drop, proving the secure default.
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        register_schema=DangerousRegister,
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        r = await c.post(
            "/register",
            json={
                "email": "a@x.com",
                "username": "a",
                "password": "pw123456",
                "full_name": "A",
                "role": "admin",
            },
        )
        assert r.status_code == 200, r.text
    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "a@x.com")
    assert user is not None
    assert user.role == "user"
    assert user.full_name is None
    await auth.shutdown()


def test_warns_at_startup_when_schema_declares_gated_field(get_session, UserModel, caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="crudauth"):
        CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY="test-secret-key-0123456789-0123456789",
            transports=[SessionTransport(cookies=CookieConfig(secure=False))],
            register_schema=DangerousRegister,
        )
    msg = caplog.text
    assert "privileged field" in msg
    assert "is_superuser" in msg
    assert "email_verified" in msg


def test_warns_when_real_column_not_opted_in(get_session, UserModel, caplog) -> None:
    class WithName(BaseModel):
        email: str
        username: str
        password: str
        full_name: str | None = None

    with caplog.at_level(logging.WARNING, logger="crudauth"):
        CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY="test-secret-key-0123456789-0123456789",
            transports=[SessionTransport(cookies=CookieConfig(secure=False))],
            register_schema=WithName,
        )
    # not a privileged field, but a real column that will silently drop -> warned
    assert "register_extra_fields" in caplog.text
    assert "full_name" in caplog.text


def test_no_warning_for_clean_schema(get_session, UserModel, caplog) -> None:
    class CleanRegister(BaseModel):
        email: str
        username: str
        password: str
        full_name: str | None = None

    with caplog.at_level(logging.WARNING, logger="crudauth"):
        CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY="test-secret-key-0123456789-0123456789",
            transports=[SessionTransport(cookies=CookieConfig(secure=False))],
            register_schema=CleanRegister,
            register_extra_fields={"full_name"},  # opted in -> nothing to warn about
        )
    assert "privileged field" not in caplog.text
    assert "will drop" not in caplog.text
