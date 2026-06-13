"""Power-user: a custom transport (the shape ApiKeyTransport will take)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from fastapi import APIRouter, Depends, FastAPI, Request

from crudauth import CRUDAuth, CookieConfig, Principal, SessionTransport
from crudauth.core import AuthContext, Transport
from crudauth.utils import get_password_hash


class ApiKeyTransport(Transport):
    name = "apikey"

    def __init__(self, store: dict[str, dict], header: str = "X-API-Key"):
        self.store = store
        self.header = header

    async def authenticate(self, request: Request, ctx: AuthContext) -> Principal | None:
        raw = request.headers.get(self.header)
        if not raw:
            return None
        record = self.store.get(raw)
        if not record or not record.get("is_active"):
            return None
        user = await ctx.resolve_user(record["user_id"])
        if user is None:
            return None
        return Principal(
            user_id=record["user_id"],
            scopes=tuple(record["scopes"]),
            transport=self.name,
            user=user,
        )

    def contributes_routes(self) -> APIRouter | None:
        return None


@pytest.fixture
async def ctx(get_session, UserModel, sessionmaker) -> AsyncIterator[tuple[Any, ...]]:
    keystore: dict[str, dict] = {}
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[
            SessionTransport(cookies=CookieConfig(secure=False)),
            ApiKeyTransport(keystore),
        ],
    )
    app = FastAPI()
    app.include_router(auth.router)

    @app.get("/v1/data")
    async def data(
        user: Principal = Depends(auth.current_user(transport="apikey", scopes=["data:read"])),
    ):
        return {"user_id": user.user_id, "via": user.transport}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c, keystore, sessionmaker, UserModel
    await auth.shutdown()


async def _make_user(sessionmaker, UserModel):
    async with sessionmaker() as db:
        user = UserModel(
            email="k@x.com", username="keyuser", hashed_password=get_password_hash("pw")
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user.id


async def test_apikey_transport_authenticates(ctx) -> None:
    client, keystore, sm, UserModel = ctx
    uid = await _make_user(sm, UserModel)
    keystore["secret-key"] = {"user_id": uid, "scopes": ["data:read"], "is_active": True}

    r = await client.get("/v1/data", headers={"X-API-Key": "secret-key"})
    assert r.status_code == 200
    assert r.json() == {"user_id": uid, "via": "apikey"}


async def test_apikey_missing_401(ctx) -> None:
    client, *_ = ctx
    r = await client.get("/v1/data")
    assert r.status_code == 401


async def test_apikey_wrong_scope_403(ctx) -> None:
    client, keystore, sm, UserModel = ctx
    uid = await _make_user(sm, UserModel)
    keystore["k2"] = {"user_id": uid, "scopes": ["other"], "is_active": True}
    r = await client.get("/v1/data", headers={"X-API-Key": "k2"})
    assert r.status_code == 403
