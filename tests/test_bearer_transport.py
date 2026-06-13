"""Bearer (JWT) transport: /token, /refresh, /me, scopes."""

from __future__ import annotations

import httpx
import pytest
from fastapi import Depends, FastAPI

from crudauth import BearerTransport, CRUDAuth, CookieConfig, Principal, SessionTransport


def build_app(get_session, UserModel):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[
            BearerTransport(access_ttl=900, refresh="cookie", cookies=CookieConfig(secure=False))
        ],
    )
    app = FastAPI()
    app.include_router(auth.router)

    @app.get("/v1/items")
    async def items(user: Principal = Depends(auth.current_user(transport="bearer"))):
        return {"user_id": user.user_id}

    @app.get("/v1/reports")
    async def reports(user: Principal = Depends(auth.current_user(scopes=["reports:read"]))):
        return {"ok": True}

    return app, auth


@pytest.fixture
async def client(get_session, UserModel):
    app, auth = build_app(get_session, UserModel)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c
    await auth.shutdown()


async def _register(client):
    await client.post(
        "/register", json={"email": "a@x.com", "username": "alice", "password": "pw123456"}
    )


async def test_token_and_access(client) -> None:
    await _register(client)
    r = await client.post("/token", data={"username": "alice", "password": "pw123456"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["token_type"] == "bearer"
    token = body["access_token"]

    r = await client.get("/v1/items", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


async def test_no_token_401(client) -> None:
    r = await client.get("/v1/items")
    assert r.status_code == 401


async def test_bad_token_401(client) -> None:
    r = await client.get("/v1/items", headers={"Authorization": "Bearer garbage"})
    assert r.status_code == 401


async def test_refresh_flow(client) -> None:
    await _register(client)
    r = await client.post("/token", data={"username": "alice", "password": "pw123456"})
    assert "refresh_token" in r.cookies  # set as httpOnly cookie
    r2 = await client.post("/refresh")
    assert r2.status_code == 200
    assert "access_token" in r2.json()


async def test_scopes_granted_via_token(client) -> None:
    await _register(client)
    # request the scope at /token (OAuth2 form 'scope' field)
    r = await client.post(
        "/token",
        data={"username": "alice", "password": "pw123456", "scope": "reports:read"},
    )
    token = r.json()["access_token"]
    r = await client.get("/v1/reports", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


async def test_scope_missing_403(client) -> None:
    await _register(client)
    r = await client.post("/token", data={"username": "alice", "password": "pw123456"})
    token = r.json()["access_token"]
    r = await client.get("/v1/reports", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403


async def test_token_shares_lockout_with_login(get_session, UserModel) -> None:
    # /token must not be a lockout bypass - it shares the counter with /login.
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[
            SessionTransport(cookies=CookieConfig(secure=False), login_max_attempts=2),
            BearerTransport(cookies=CookieConfig(secure=False)),
        ],
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        await c.post(
            "/register", json={"email": "a@x.com", "username": "alice", "password": "pw123456"}
        )
        for _ in range(3):  # trip the lockout via /login
            await c.post("/login", data={"username": "alice", "password": "wrong"})
        # /token is blocked by the SAME lockout - even a correct password
        assert (
            await c.post("/token", data={"username": "alice", "password": "wrong"})
        ).status_code == 429
        assert (
            await c.post("/token", data={"username": "alice", "password": "pw123456"})
        ).status_code == 429
    await auth.shutdown()


async def test_token_lockout_blocks_login_too(get_session, UserModel) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[
            SessionTransport(cookies=CookieConfig(secure=False), login_max_attempts=2),
            BearerTransport(cookies=CookieConfig(secure=False)),
        ],
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        await c.post(
            "/register", json={"email": "a@x.com", "username": "alice", "password": "pw123456"}
        )
        for _ in range(3):  # trip via /token
            await c.post("/token", data={"username": "alice", "password": "wrong"})
        assert (
            await c.post("/login", data={"username": "alice", "password": "wrong"})
        ).status_code == 429
    await auth.shutdown()
