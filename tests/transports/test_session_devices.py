"""Multi-device session management exposed via auth.sessions (cookbook F3)."""

from __future__ import annotations

import httpx
import pytest
from fastapi import Depends, FastAPI

from crudauth import CRUDAuth, CookieConfig, Principal, SessionTransport


@pytest.fixture
async def ctx(get_session, UserModel):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()
    app.include_router(auth.router)

    @app.get("/account/sessions")
    async def my_sessions(user: Principal = Depends(auth.current_user(transport="session"))):
        return await auth.sessions.list_for_user(user.user_id)

    @app.post("/account/logout-all")
    async def logout_all(user: Principal = Depends(auth.current_user(transport="session"))):
        return {"revoked": await auth.sessions.revoke_all(user.user_id)}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c, auth
    await auth.shutdown()


async def test_list_sessions(ctx) -> None:
    client, auth = ctx
    await client.post(
        "/register", json={"email": "a@x.com", "username": "alice", "password": "pw123456"}
    )
    await client.post("/login", data={"username": "alice", "password": "pw123456"})
    r = await client.get("/account/sessions")
    assert r.status_code == 200
    sessions = r.json()
    assert len(sessions) == 1
    assert "device" in sessions[0] and "last_activity" in sessions[0]


async def test_logout_all_revokes(ctx) -> None:
    client, auth = ctx
    await client.post(
        "/register", json={"email": "a@x.com", "username": "alice", "password": "pw123456"}
    )
    login = await client.post("/login", data={"username": "alice", "password": "pw123456"})
    csrf = login.json()["csrf_token"]
    r = await client.post("/account/logout-all", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    assert r.json()["revoked"] >= 1
    # session no longer valid
    r = await client.get("/account/sessions")
    assert r.status_code == 401
