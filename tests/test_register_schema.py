"""Optional custom registration schema: opted-in extra fields persist (not required)."""

from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI
from pydantic import BaseModel

from crudauth import CookieConfig, CRUDAuth, SessionTransport
from crudauth.repository import UserRepository


class RegisterWithName(BaseModel):
    email: str
    username: str
    password: str
    full_name: str


@pytest.fixture
async def ctx(get_session, UserModel, sessionmaker):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        register_schema=RegisterWithName,
        register_extra_fields={"full_name"},
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c, sessionmaker, UserModel
    await auth.shutdown()


async def test_custom_field_persisted(ctx) -> None:
    client, sessionmaker, UserModel = ctx
    r = await client.post(
        "/register",
        json={
            "email": "a@x.com",
            "username": "alice",
            "password": "pw123456",
            "full_name": "Alice Doe",
        },
    )
    assert r.status_code == 200, r.text

    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "a@x.com")
    assert user is not None
    assert user.full_name == "Alice Doe"


async def test_custom_schema_requires_its_fields(ctx) -> None:
    client, *_ = ctx
    # full_name is required by the custom schema → 422 when missing
    r = await client.post(
        "/register",
        json={"email": "b@x.com", "username": "bob", "password": "pw123456"},
    )
    assert r.status_code == 422


async def test_default_schema_still_works(get_session, UserModel) -> None:
    # No register_schema → the built-in 3-field body is used.
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        r = await c.post(
            "/register", json={"email": "c@x.com", "username": "carol", "password": "pw123456"}
        )
        assert r.status_code == 200
    await auth.shutdown()
