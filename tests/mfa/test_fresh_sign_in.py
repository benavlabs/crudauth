"""A passwordless account proves a fresh sign-in before it adds a lasting credential.

An OAuth-only account has no password to re-enter, so ``/mfa/totp/setup`` and
``/set-password`` used to accept any session cookie: a stolen one could attach the
thief's authenticator, or a password (then the email, then everything).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest
from fastapi import Depends, Request
from starlette.requests import Request as StarletteRequest

from crudauth import BearerTransport, CookieConfig, MfaConfig, SessionTransport, SudoConfig
from crudauth.principal import Principal
from crudauth.transports.session.schemas import SessionData
from crudauth.utils import make_unusable_password

from .conftest import MFA_KEY, PASSWORD, client, code_for, register_and_login
from tests.conftest import mounted_paths

STALE = timedelta(minutes=11)


def _request() -> StarletteRequest:
    return StarletteRequest(
        {"type": "http", "method": "GET", "headers": [], "client": ("1.2.3.4", 1234)}
    )


async def _passwordless(auth: Any, mfa_sessionmaker: Any) -> Any:
    async with mfa_sessionmaker() as db:
        user = await auth.repo.create(
            db,
            {
                "email": "oauth@x.com",
                "username": "oauth",
                "hashed_password": make_unusable_password(),
                "email_verified": True,
            },
        )
        return auth.repo.user_id(user)


async def _signed_in(auth: Any, user_id: Any, *, age: timedelta = timedelta(0)) -> dict[str, str]:
    """A session the way an OAuth sign-in leaves it, signed in ``age`` ago."""
    session_id, csrf = await auth.sessions.create_session(_request(), user_id=user_id)
    if age:

        def backdate(session: SessionData) -> None:
            session.created_at = datetime.now(timezone.utc) - age

        await auth.sessions.modify_session(session_id, backdate)
    return {"session_id": session_id, "csrf": csrf}


def _browser(app: Any, credentials: dict[str, str]) -> httpx.AsyncClient:
    browser = client(app)
    browser.cookies.set("session_id", credentials["session_id"], domain="test.local")
    browser.headers["X-CSRF-Token"] = credentials["csrf"]
    return browser


async def test_a_passwordless_account_signed_in_long_ago_cannot_start_mfa_setup(
    build, mfa_sessionmaker
) -> None:
    auth, app = build()
    user_id = await _passwordless(auth, mfa_sessionmaker)
    credentials = await _signed_in(auth, user_id, age=STALE)

    async with _browser(app, credentials) as browser:
        setup = await browser.post("/mfa/totp/setup", json={})
        password = await browser.post("/set-password", json={"new_password": "brand-new-pw-1"})

    assert setup.status_code == 403
    assert "sign in again" in setup.json()["detail"].lower()
    assert password.status_code == 403


async def test_a_fresh_sign_in_can_set_up_mfa_and_a_password(build, mfa_sessionmaker) -> None:
    auth, app = build()
    user_id = await _passwordless(auth, mfa_sessionmaker)
    credentials = await _signed_in(auth, user_id)

    async with _browser(app, credentials) as browser:
        setup = await browser.post("/mfa/totp/setup", json={})
        confirm = await browser.post(
            "/mfa/totp/confirm", json={"code": code_for(setup.json()["secret"])}
        )
        password = await browser.post("/set-password", json={"new_password": "brand-new-pw-1"})

    assert setup.status_code == 200
    assert confirm.status_code == 200
    assert password.status_code == 200


async def test_the_window_is_configurable_and_zero_closes_the_routes(
    build, mfa_sessionmaker
) -> None:
    auth, app = build(fresh_sign_in_seconds=0)
    user_id = await _passwordless(auth, mfa_sessionmaker)
    credentials = await _signed_in(auth, user_id)

    async with _browser(app, credentials) as browser:
        setup = await browser.post("/mfa/totp/setup", json={})
        password = await browser.post("/set-password", json={"new_password": "brand-new-pw-1"})

    assert setup.status_code == password.status_code == 403


async def test_a_wider_window_accepts_an_older_sign_in(build, mfa_sessionmaker) -> None:
    auth, app = build(fresh_sign_in_seconds=3600)
    user_id = await _passwordless(auth, mfa_sessionmaker)
    credentials = await _signed_in(auth, user_id, age=STALE)

    async with _browser(app, credentials) as browser:
        setup = await browser.post("/mfa/totp/setup", json={})

    assert setup.status_code == 200


async def test_an_account_with_a_password_still_proves_it_with_the_password(build) -> None:
    """Unchanged: the password is the proof, however old the session."""
    auth, app = build()

    async with client(app) as browser:
        login = await register_and_login(browser)
        csrf = login.json()["csrf_token"]
        session_id = browser.cookies["session_id"]

        def backdate(session: SessionData) -> None:
            session.created_at = datetime.now(timezone.utc) - STALE

        await auth.sessions.modify_session(session_id, backdate)
        headers = {"X-CSRF-Token": csrf}
        wrong = await browser.post("/mfa/totp/setup", json={"password": "nope"}, headers=headers)
        right = await browser.post("/mfa/totp/setup", json={"password": PASSWORD}, headers=headers)

    assert wrong.status_code == 401
    assert right.status_code == 200


async def test_an_active_sudo_elevation_counts_as_fresh(build, mfa_sessionmaker) -> None:
    """An enrolled passwordless account, signed in long ago, elevates with its authenticator
    and may then set a password."""
    auth, app = build(sudo=SudoConfig())
    sudo = auth.sudo
    assert sudo is not None

    @app.post("/sudo")
    async def elevate(
        body: dict,
        request: Request,
        principal: Principal = Depends(auth.current_user()),
        db: Any = Depends(auth.session),
    ) -> dict[str, bool]:
        await sudo.elevate(principal, code=body["code"], db=db, request=request)
        return {"elevated": True}

    user_id = await _passwordless(auth, mfa_sessionmaker)
    fresh = await _signed_in(auth, user_id)
    async with _browser(app, fresh) as browser:
        secret = (await browser.post("/mfa/totp/setup", json={})).json()["secret"]
        await browser.post("/mfa/totp/confirm", json={"code": code_for(secret, -1)})

    stale = await _signed_in(auth, user_id, age=STALE)
    async with _browser(app, stale) as browser:
        before = await browser.post("/set-password", json={"new_password": "brand-new-pw-1"})
        elevated = await browser.post("/sudo", json={"code": code_for(secret)})
        after = await browser.post("/set-password", json={"new_password": "brand-new-pw-1"})

    assert before.status_code == 403
    assert elevated.status_code == 200
    assert after.status_code == 200


async def test_a_bearer_token_cannot_show_when_the_account_signed_in(
    build, mfa_sessionmaker
) -> None:
    """Access tokens are re-minted on refresh without a sign-in, so they prove nothing fresh."""
    bearer = BearerTransport()
    auth, app = build(transports=[SessionTransport(cookies=CookieConfig(secure=False)), bearer])
    user_id = await _passwordless(auth, mfa_sessionmaker)
    async with mfa_sessionmaker() as db:
        user = await auth.repo.get_by_id(db, user_id)
    token = bearer.issue_tokens(user)["access_token"]

    async with client(app) as browser:
        headers = {"Authorization": f"Bearer {token}"}
        setup = await browser.post("/mfa/totp/setup", json={}, headers=headers)
        password = await browser.post(
            "/set-password", json={"new_password": "brand-new-pw-1"}, headers=headers
        )

    assert setup.status_code == password.status_code == 403


async def test_signed_in_recently_is_public_for_an_apps_own_routes(build, mfa_sessionmaker) -> None:
    auth, app = build()

    @app.get("/fresh")
    async def fresh(principal: Principal = Depends(auth.current_user())) -> dict[str, bool]:
        return {"fresh": await auth.signed_in_recently(principal)}

    user_id = await _passwordless(auth, mfa_sessionmaker)
    async with _browser(app, await _signed_in(auth, user_id)) as browser:
        now = (await browser.get("/fresh")).json()
    async with _browser(app, await _signed_in(auth, user_id, age=STALE)) as browser:
        old = (await browser.get("/fresh")).json()

    assert now == {"fresh": True}
    assert old == {"fresh": False}


def test_the_mfa_router_can_be_mounted_on_its_own(build) -> None:
    auth, _ = build()

    paths = mounted_paths(auth.mfa_router)

    assert "/mfa/totp/setup" in paths
    assert "/mfa/verify" in paths
    assert "/register" not in paths


def test_the_mfa_router_needs_mfa_configured(get_session, UserModel) -> None:
    from crudauth import CRUDAuth

    auth = CRUDAuth(session=get_session, user_model=UserModel, SECRET_KEY="s" * 32)

    with pytest.raises(RuntimeError, match="MFA is not configured"):
        auth.mfa_router


def test_the_window_cannot_be_negative(build) -> None:
    with pytest.raises(ValueError, match="fresh_sign_in_seconds"):
        build(mfa=MfaConfig(issuer="Acme", encryption_key=MFA_KEY), fresh_sign_in_seconds=-1)
