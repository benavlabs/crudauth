"""POST /set-password: OAuth-only accounts establish a password while authenticated."""

from __future__ import annotations

import httpx
from fastapi import FastAPI
from starlette.requests import Request

from crudauth import CRUDAuth, CookieConfig, SessionTransport
from crudauth.repository import UserRepository
from crudauth.utils import get_password_hash, make_unusable_password

SECRET = "test-secret-key-0123456789-0123456789"


def _request() -> Request:
    return Request({"type": "http", "method": "GET", "headers": [], "client": ("1.2.3.4", 1234)})


def _build(get_session, UserModel):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()
    app.include_router(auth.router)
    return app, auth


async def _make_user(repo, sessionmaker, *, username, password_hash):
    async with sessionmaker() as db:
        user = await repo.create(
            db,
            {"email": f"{username}@x.com", "username": username, "hashed_password": password_hash},
        )
        return repo.user_id(user)


async def test_oauth_only_account_can_set_password(get_session, UserModel, sessionmaker) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    repo = UserRepository(UserModel)
    uid = await _make_user(repo, sessionmaker, username="o", password_hash=make_unusable_password())
    # OAuth establishes a session; mint one directly (the account has no password)
    sid, csrf = await auth.sessions.create_session(_request(), user_id=uid)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test", cookies={"session_id": sid}
    ) as c:
        r = await c.post(
            "/set-password", json={"new_password": "newpw12345"}, headers={"X-CSRF-Token": csrf}
        )
        assert r.status_code == 200, r.text
        # the account can now log in with the password it just set
        login = await c.post("/login", data={"username": "o", "password": "newpw12345"})
        assert login.status_code == 200
    await auth.shutdown()


async def test_set_password_refused_when_password_exists(
    get_session, UserModel, sessionmaker
) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    repo = UserRepository(UserModel)
    uid = await _make_user(
        repo, sessionmaker, username="p", password_hash=get_password_hash("pw123456")
    )
    sid, csrf = await auth.sessions.create_session(_request(), user_id=uid)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test", cookies={"session_id": sid}
    ) as c:
        r = await c.post(
            "/set-password", json={"new_password": "newpw12345"}, headers={"X-CSRF-Token": csrf}
        )
        assert r.status_code == 400  # already has a usable password → use reset instead
    await auth.shutdown()


async def test_set_password_requires_authentication(get_session, UserModel) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        r = await c.post("/set-password", json={"new_password": "newpw12345"})
        assert r.status_code == 401
    await auth.shutdown()


async def test_set_password_enforces_min_length(get_session, UserModel, sessionmaker) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    repo = UserRepository(UserModel)
    uid = await _make_user(repo, sessionmaker, username="s", password_hash=make_unusable_password())
    sid, csrf = await auth.sessions.create_session(_request(), user_id=uid)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test", cookies={"session_id": sid}
    ) as c:
        r = await c.post(
            "/set-password", json={"new_password": "short"}, headers={"X-CSRF-Token": csrf}
        )
        assert r.status_code == 422
    await auth.shutdown()
