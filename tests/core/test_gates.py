"""Authorization gates: superuser, verified, scopes, and the check= override."""

from __future__ import annotations

import httpx
import pytest
from fastapi import Depends, FastAPI

from crudauth import CRUDAuth, CookieConfig, ForbiddenException, Principal, SessionTransport
from crudauth.utils import get_password_hash


def superuser_with_domain(user: Principal) -> None:
    if not user.user.email.endswith("@company.com"):
        raise ForbiddenException("Insufficient privileges")


def build_app(get_session, UserModel):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()
    app.include_router(auth.router)

    @app.get("/admin")
    async def admin(_: Principal = Depends(auth.current_user(superuser=True))):
        return {"ok": True}

    @app.post("/posts")
    async def posts(_: Principal = Depends(auth.current_user(verified=True))):
        return {"ok": True}

    @app.get("/admin/users")
    async def admin_users(
        _: Principal = Depends(auth.current_user(superuser=True, check=superuser_with_domain)),
    ):
        return {"ok": True}

    # boolean-predicate style: returns False for non-superusers
    @app.get("/bool-gate")
    async def bool_gate(_: Principal = Depends(auth.current_user(check=lambda p: p.is_superuser))):
        return {"ok": True}

    async def _async_check(p: Principal) -> bool:
        return p.is_superuser

    @app.get("/async-gate")
    async def async_gate(_: Principal = Depends(auth.current_user(check=_async_check))):
        return {"ok": True}

    @app.get("/falsy-gate")
    async def falsy_gate(_: Principal = Depends(auth.current_user(check=lambda p: 0))):
        return {"ok": True}

    return app, auth


@pytest.fixture
async def ctx(get_session, UserModel, sessionmaker):
    app, auth = build_app(get_session, UserModel)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c, sessionmaker, UserModel
    await auth.shutdown()


async def _make_user(sessionmaker, UserModel, **flags):
    async with sessionmaker() as db:
        user = UserModel(
            email=flags.pop("email", "u@x.com"),
            username=flags.pop("username", "u"),
            hashed_password=get_password_hash("pw123456"),
            **flags,
        )
        db.add(user)
        await db.commit()


async def _login(client, username="u"):
    return await client.post("/login", data={"username": username, "password": "pw123456"})


async def test_disabled_account_login_is_uniform(ctx) -> None:
    # a disabled account with the CORRECT password gets the same message as bad
    # credentials - no exists-but-disabled oracle for a credential holder.
    client, sm, UserModel = ctx
    await _make_user(sm, UserModel, is_active=False)
    r = await _login(client)  # correct password, but account disabled
    assert r.status_code == 401
    assert r.json()["detail"] == "Incorrect username or password"


async def test_superuser_gate_blocks_normal(ctx) -> None:
    client, sm, UserModel = ctx
    await _make_user(sm, UserModel, is_superuser=False)
    await _login(client)
    r = await client.get("/admin")
    assert r.status_code == 403


async def test_superuser_gate_allows_superuser(ctx) -> None:
    client, sm, UserModel = ctx
    await _make_user(sm, UserModel, is_superuser=True)
    await _login(client)
    r = await client.get("/admin")
    assert r.status_code == 200


async def test_verified_gate(ctx) -> None:
    client, sm, UserModel = ctx
    await _make_user(sm, UserModel, email_verified=False)
    login = await _login(client)
    csrf = login.json()["csrf_token"]
    r = await client.post("/posts", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 403


async def test_check_override_domain(ctx) -> None:
    client, sm, UserModel = ctx
    await _make_user(sm, UserModel, email="admin@company.com", username="boss", is_superuser=True)
    await _login(client, username="boss")
    r = await client.get("/admin/users")
    assert r.status_code == 200


async def test_check_override_rejects_wrong_domain(ctx) -> None:
    client, sm, UserModel = ctx
    await _make_user(sm, UserModel, email="admin@evil.com", username="sneaky", is_superuser=True)
    await _login(client, username="sneaky")
    r = await client.get("/admin/users")
    assert r.status_code == 403


async def test_bool_check_false_denies(ctx) -> None:
    # a predicate returning False must DENY (the bug: it was previously ignored)
    client, sm, UserModel = ctx
    await _make_user(sm, UserModel, username="plain", is_superuser=False)
    await _login(client, username="plain")
    r = await client.get("/bool-gate")
    assert r.status_code == 403


async def test_bool_check_true_allows(ctx) -> None:
    client, sm, UserModel = ctx
    await _make_user(sm, UserModel, username="boss", is_superuser=True)
    await _login(client, username="boss")
    r = await client.get("/bool-gate")
    assert r.status_code == 200


async def test_async_check_false_denies(ctx) -> None:
    client, sm, UserModel = ctx
    await _make_user(sm, UserModel, username="plain", is_superuser=False)
    await _login(client, username="plain")
    r = await client.get("/async-gate")
    assert r.status_code == 403


async def test_async_check_true_allows(ctx) -> None:
    client, sm, UserModel = ctx
    await _make_user(sm, UserModel, username="boss", is_superuser=True)
    await _login(client, username="boss")
    r = await client.get("/async-gate")
    assert r.status_code == 200


async def test_falsy_but_not_false_check_allows(ctx) -> None:
    # Only the False singleton denies; falsy-but-not-False (here 0) allows. This
    # is the discriminator that lets raise-style callbacks (return None on
    # success) coexist with boolean predicates - pinned so a change to
    # `not result` is caught.
    client, sm, UserModel = ctx
    await _make_user(sm, UserModel, username="plain", is_superuser=False)
    await _login(client, username="plain")
    r = await client.get("/falsy-gate")
    assert r.status_code == 200
