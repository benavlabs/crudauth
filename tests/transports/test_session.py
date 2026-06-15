"""Session (cookie) transport: register, login, /me, optional, CSRF, logout."""

from __future__ import annotations

import httpx
import pytest
from fastapi import Depends, FastAPI

from crudauth import CRUDAuth, CookieConfig, Principal, SessionTransport


def build_app(get_session, UserModel):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()
    app.include_router(auth.router)

    @app.get("/dashboard")
    async def dashboard(me: Principal = Depends(auth.current_user())):
        return {"hello": me.user.username, "via": me.transport}

    @app.get("/feed")
    async def feed(me: Principal | None = Depends(auth.current_user(optional=True))):
        return {"auth": me is not None}

    @app.post("/account/settings")
    async def settings(me: Principal = Depends(auth.current_user(transport="session"))):
        return {"ok": True}

    return app, auth


@pytest.fixture
async def client(get_session, UserModel):
    app, auth = build_app(get_session, UserModel)
    await auth.initialize()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    await auth.shutdown()


async def _register(client):
    r = await client.post(
        "/register",
        json={"email": "a@x.com", "username": "alice", "password": "pw123456"},
    )
    assert r.status_code == 200, r.text
    return r.json()


async def test_register_and_login_and_me(client) -> None:
    user = await _register(client)
    assert user["email"] == "a@x.com"

    r = await client.post("/login", data={"username": "alice", "password": "pw123456"})
    assert r.status_code == 200, r.text
    assert "csrf_token" in r.json()

    r = await client.get("/dashboard")
    assert r.status_code == 200
    assert r.json() == {"hello": "alice", "via": "session"}


async def test_login_by_email(client) -> None:
    await _register(client)
    r = await client.post("/login", data={"username": "a@x.com", "password": "pw123456"})
    assert r.status_code == 200


async def test_wrong_password_401(client) -> None:
    await _register(client)
    r = await client.post("/login", data={"username": "alice", "password": "wrong"})
    assert r.status_code == 401


async def test_required_route_without_auth_401(client) -> None:
    r = await client.get("/dashboard")
    assert r.status_code == 401


async def test_optional_route_works_logged_out(client) -> None:
    r = await client.get("/feed")
    assert r.status_code == 200
    assert r.json() == {"auth": False}


async def test_csrf_enforced_on_session_mutation(client) -> None:
    await _register(client)
    login = await client.post("/login", data={"username": "alice", "password": "pw123456"})
    csrf = login.json()["csrf_token"]

    # Without the header → 403
    r = await client.post("/account/settings")
    assert r.status_code == 403

    # With the header → ok
    r = await client.post("/account/settings", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200


async def test_logout_clears_session(client) -> None:
    await _register(client)
    login = await client.post("/login", data={"username": "alice", "password": "pw123456"})
    csrf = login.json()["csrf_token"]
    r = await client.post("/logout", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    r = await client.get("/dashboard")
    assert r.status_code == 401


async def test_duplicate_email_rejected(client) -> None:
    await _register(client)
    r = await client.post(
        "/register", json={"email": "a@x.com", "username": "bob", "password": "pw123456"}
    )
    assert r.status_code == 422


async def test_login_lockout_returns_429(get_session, UserModel) -> None:
    # Tight lockout so a few wrong-password posts trip it over HTTP - exercises
    # transport → runtime rate-limiter backend → LockoutPolicy end to end.
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False), login_max_attempts=2)],
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
        statuses = [
            (await c.post("/login", data={"username": "alice", "password": "wrong"})).status_code
            for _ in range(3)
        ]
        assert statuses[0] == 401  # bad creds before the cap
        assert 429 in statuses  # lockout trips once over the attempt cap
        locked = await c.post("/login", data={"username": "alice", "password": "wrong"})
        assert locked.status_code == 429
        assert "Retry-After" in locked.headers
    await auth.shutdown()


async def test_login_lockout_not_bypassable_by_email_case(get_session, UserModel) -> None:
    # Case variants of one email must collapse to a single lockout key, so an
    # attacker can't reset the per-user counter by varying case.
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False), login_max_attempts=2)],
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        await c.post(
            "/register", json={"email": "v@x.com", "username": "victim", "password": "pw123456"}
        )
        variants = ["v@x.com", "V@x.com", "v@X.com", "V@X.COM"]
        statuses = [
            (await c.post("/login", data={"username": v, "password": "wrong"})).status_code
            for v in variants
        ]
        assert 429 in statuses  # despite four distinct spellings, one account locks
    await auth.shutdown()
