"""Multiple transports: first-wins precedence and per-endpoint narrowing."""

from __future__ import annotations

from datetime import timedelta

import httpx
from fastapi import Depends, FastAPI

from crudauth import BearerTransport, CRUDAuth, CookieConfig, Principal, SessionTransport
from crudauth.transports.bearer.tokens import TokenType, create_access_token, verify_token

SECRET = "test-secret-key-0123456789-0123456789"


def build_app(get_session, UserModel, session_first=True):
    transports = (
        [SessionTransport(cookies=CookieConfig(secure=False)), BearerTransport()]
        if session_first
        else [BearerTransport(), SessionTransport(cookies=CookieConfig(secure=False))]
    )
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=transports,
    )
    app = FastAPI()
    app.include_router(auth.router)

    @app.get("/me2")
    async def me2(user: Principal = Depends(auth.current_user())):
        return {"via": user.transport}

    @app.get("/bearer-only")
    async def bearer_only(user: Principal = Depends(auth.current_user(transport="bearer"))):
        return {"via": user.transport}

    return app, auth


async def _client(app, auth):
    await auth.initialize()
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def _setup(client):
    await client.post(
        "/register", json={"email": "a@x.com", "username": "alice", "password": "pw123456"}
    )
    login = await client.post("/login", data={"username": "alice", "password": "pw123456"})
    token = (
        await client.post("/token", data={"username": "alice", "password": "pw123456"})
    ).json()["access_token"]
    return login.json()["csrf_token"], token


async def test_session_first_wins(get_session, UserModel) -> None:
    app, auth = build_app(get_session, UserModel, session_first=True)
    async with await _client(app, auth) as client:
        _, token = await _setup(client)
        # both credentials present (session cookie + bearer header) → session wins
        r = await client.get("/me2", headers={"Authorization": f"Bearer {token}"})
        assert r.json()["via"] == "session"
    await auth.shutdown()


async def test_bearer_first_wins(get_session, UserModel) -> None:
    app, auth = build_app(get_session, UserModel, session_first=False)
    async with await _client(app, auth) as client:
        _, token = await _setup(client)
        r = await client.get("/me2", headers={"Authorization": f"Bearer {token}"})
        assert r.json()["via"] == "bearer"
    await auth.shutdown()


async def test_narrow_to_bearer_ignores_session(get_session, UserModel) -> None:
    app, auth = build_app(get_session, UserModel, session_first=True)
    async with await _client(app, auth) as client:
        _, token = await _setup(client)
        # session cookie present but endpoint only accepts bearer → must use header
        r = await client.get("/bearer-only")
        assert r.status_code == 401
        r = await client.get("/bearer-only", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["via"] == "bearer"
    await auth.shutdown()


async def test_bearer_first_invalid_token_hard_fails(get_session, UserModel) -> None:
    # an invalid bearer token is a present-but-invalid credential,
    # so when bearer runs first it hard-fails (401) rather than falling through to
    # the valid session cookie.
    app, auth = build_app(get_session, UserModel, session_first=False)
    async with await _client(app, auth) as client:
        await _setup(client)  # establishes a valid session cookie
        r = await client.get("/me2", headers={"Authorization": "Bearer garbage"})
        assert r.status_code == 401
    await auth.shutdown()


async def test_expired_bearer_falls_through_to_session(get_session, UserModel) -> None:
    # bearer first; an EXPIRED (not tampered) access token is treated as no
    # credential, so a valid session cookie still authenticates the request.
    app, auth = build_app(get_session, UserModel, session_first=False)
    async with await _client(app, auth) as client:
        _, token = await _setup(client)  # valid session cookie + valid bearer token
        payload = verify_token(token, SECRET, TokenType.ACCESS)
        assert payload is not None
        expired = create_access_token(
            {"sub": payload["sub"]}, SECRET, expires_delta=timedelta(seconds=-1)
        )
        r = await client.get("/me2", headers={"Authorization": f"Bearer {expired}"})
        assert r.status_code == 200
        assert r.json()["via"] == "session"
    await auth.shutdown()


async def test_session_first_bad_bearer_never_reached(get_session, UserModel) -> None:
    # With session first, a valid session wins before the bad bearer token is even
    # evaluated - order is the policy lever.
    app, auth = build_app(get_session, UserModel, session_first=True)
    async with await _client(app, auth) as client:
        await _setup(client)
        r = await client.get("/me2", headers={"Authorization": "Bearer garbage"})
        assert r.status_code == 200
        assert r.json()["via"] == "session"
    await auth.shutdown()
