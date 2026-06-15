"""Sudo mode: short-lived re-authentication, its lockout, and require_sudo()."""

from __future__ import annotations

import httpx
import pytest
from fastapi import Depends, FastAPI, Request
from starlette.requests import Request as StarletteRequest

from crudauth import CRUDAuth, CookieConfig, SessionTransport, SudoConfig
from crudauth.exceptions import ForbiddenException
from crudauth.principal import Principal
from crudauth.repository import UserRepository
from crudauth.transports.bearer.transport import BearerTransport
from crudauth.transports.session.constants import SUDO_ELEVATED_UNTIL_META_KEY
from crudauth.transports.session.schemas import SessionData
from crudauth.utils import get_password_hash

SECRET = "test-secret-key-0123456789-0123456789"
PASSWORD = "rightpw123"


def _request() -> StarletteRequest:
    return StarletteRequest(
        {"type": "http", "method": "GET", "headers": [], "client": ("1.2.3.4", 1234)}
    )


def _build(get_session, UserModel, *, sudo: SudoConfig | None = SudoConfig()):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        sudo=sudo,
    )
    app = FastAPI()
    app.include_router(auth.router)

    sudo_mgr = auth.sudo
    assert sudo_mgr is not None

    @app.post("/sudo")
    async def do_sudo(
        request: Request,
        body: dict,
        principal: Principal = Depends(auth.current_user()),
    ):
        until = await sudo_mgr.elevate(principal, body["password"], request=request)
        return {"elevated_until": until.isoformat()}

    @app.get("/sudo-state")
    async def sudo_state(principal: Principal = Depends(auth.current_user())):
        return {"elevated": await sudo_mgr.is_elevated(principal)}

    @app.post("/danger")
    async def danger(_: Principal = Depends(auth.require_sudo())):
        return {"ok": True}

    return app, auth


async def _make_user(repo, sessionmaker, *, username="u"):
    async with sessionmaker() as db:
        user = await repo.create(
            db,
            {
                "email": f"{username}@x.com",
                "username": username,
                "hashed_password": get_password_hash(PASSWORD),
            },
        )
        return repo.user_id(user)


async def _client(app, sid):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test", cookies={"session_id": sid}
    )


async def test_elevate_then_require_sudo_passes(get_session, UserModel, sessionmaker) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    repo = UserRepository(UserModel)
    uid = await _make_user(repo, sessionmaker)
    sid, csrf = await auth.sessions.create_session(_request(), user_id=uid)
    async with await _client(app, sid) as c:
        h = {"X-CSRF-Token": csrf}
        assert (await c.post("/danger", headers=h)).status_code == 403  # not yet elevated
        r = await c.post("/sudo", json={"password": PASSWORD}, headers=h)
        assert r.status_code == 200, r.text
        assert (await c.get("/sudo-state")).json()["elevated"] is True
        assert (await c.post("/danger", headers=h)).status_code == 200
    await auth.shutdown()


async def test_stamp_expiry_drops_elevation(get_session, UserModel, sessionmaker) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    repo = UserRepository(UserModel)
    uid = await _make_user(repo, sessionmaker)
    sid, csrf = await auth.sessions.create_session(_request(), user_id=uid)
    async with await _client(app, sid) as c:
        h = {"X-CSRF-Token": csrf}
        await c.post("/sudo", json={"password": PASSWORD}, headers=h)
        # rewrite the stamp into the past (an absolute expiry, not sliding)
        session = await auth.sessions.storage.get(sid, SessionData)
        session.metadata[SUDO_ELEVATED_UNTIL_META_KEY] = "2000-01-01T00:00:00+00:00"
        await auth.sessions.storage.update(sid, session)
        assert (await c.get("/sudo-state")).json()["elevated"] is False
        assert (await c.post("/danger", headers=h)).status_code == 403
    await auth.shutdown()


async def test_wrong_password_is_401(get_session, UserModel, sessionmaker) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    repo = UserRepository(UserModel)
    uid = await _make_user(repo, sessionmaker)
    sid, csrf = await auth.sessions.create_session(_request(), user_id=uid)
    async with await _client(app, sid) as c:
        r = await c.post("/sudo", json={"password": "nope"}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 401
    await auth.shutdown()


async def test_sudo_lockout_after_max_attempts(get_session, UserModel, sessionmaker) -> None:
    app, auth = _build(get_session, UserModel, sudo=SudoConfig(max_attempts=3, lockout_seconds=900))
    await auth.initialize()
    repo = UserRepository(UserModel)
    uid = await _make_user(repo, sessionmaker)
    sid, csrf = await auth.sessions.create_session(_request(), user_id=uid)
    async with await _client(app, sid) as c:
        h = {"X-CSRF-Token": csrf}
        for _ in range(2):
            assert (await c.post("/sudo", json={"password": "x"}, headers=h)).status_code == 401
        r = await c.post("/sudo", json={"password": "x"}, headers=h)  # 3rd trips the lock
        assert r.status_code == 429
        assert int(r.headers["retry-after"]) == 900
        # even the correct password is now refused while locked
        assert (await c.post("/sudo", json={"password": PASSWORD}, headers=h)).status_code == 429
    await auth.shutdown()


async def test_sudo_lockout_does_not_block_login(get_session, UserModel, sessionmaker) -> None:
    app, auth = _build(get_session, UserModel, sudo=SudoConfig(max_attempts=2))
    await auth.initialize()
    repo = UserRepository(UserModel)
    uid = await _make_user(repo, sessionmaker)
    sid, csrf = await auth.sessions.create_session(_request(), user_id=uid)
    async with await _client(app, sid) as c:
        h = {"X-CSRF-Token": csrf}
        for _ in range(2):
            await c.post("/sudo", json={"password": "x"}, headers=h)
        assert (await c.post("/sudo", json={"password": "x"}, headers=h)).status_code == 429
        # login lockout is a separate namespace; logging in still works
        login = await c.post("/login", data={"username": "u", "password": PASSWORD})
        assert login.status_code == 200
    await auth.shutdown()


async def test_non_session_principal_forbidden(get_session, UserModel, sessionmaker) -> None:
    _, auth = _build(get_session, UserModel)
    await auth.initialize()
    assert auth.sudo is not None
    bearer = Principal(user_id=1, transport="bearer", user=None, metadata={})
    with pytest.raises(ForbiddenException):
        await auth.sudo.elevate(bearer, PASSWORD)
    await auth.shutdown()


async def test_logout_clears_elevation(get_session, UserModel, sessionmaker) -> None:
    app, auth = _build(get_session, UserModel)
    await auth.initialize()
    repo = UserRepository(UserModel)
    uid = await _make_user(repo, sessionmaker)
    sid, csrf = await auth.sessions.create_session(_request(), user_id=uid)
    async with await _client(app, sid) as c:
        h = {"X-CSRF-Token": csrf}
        await c.post("/sudo", json={"password": PASSWORD}, headers=h)
        assert (await c.post("/danger", headers=h)).status_code == 200
        await c.post("/logout", headers=h)
        # session is gone: both identity and elevation are lost
        assert (await c.post("/danger", headers=h)).status_code == 401
    # a principal pointing at the now-dead session is not elevated
    assert auth.sudo is not None
    ghost = Principal(user_id=uid, transport="session", user=None, metadata={"session_id": sid})
    assert await auth.sudo.is_elevated(ghost) is False
    await auth.shutdown()


def test_require_sudo_without_config_raises(get_session, UserModel) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    assert auth.sudo is None
    with pytest.raises(RuntimeError):
        auth.require_sudo()


def test_sudo_without_session_transport_raises(get_session, UserModel) -> None:
    with pytest.raises(ValueError):
        CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY=SECRET,
            transports=[BearerTransport()],
            sudo=SudoConfig(),
        )
