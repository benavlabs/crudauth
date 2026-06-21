"""Bearer (JWT) transport: /token, /refresh, /me, scopes."""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest
from fastapi import Depends, FastAPI

from crudauth import (
    BearerTransport,
    CookieConfig,
    CRUDAuth,
    EmailConfig,
    EmailContext,
    EmailSender,
    Principal,
    SessionTransport,
)
from crudauth.transports.bearer.tokens import TokenType, create_access_token, verify_token

SECRET = "test-secret-key-0123456789-0123456789"


def build_app(get_session, UserModel):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[
            BearerTransport(
                access_ttl=900,
                refresh="cookie",
                cookies=CookieConfig(secure=False),
                grantable_scopes=["reports:read"],
            )
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

    @app.get("/v1/maybe")
    async def maybe(user: Principal | None = Depends(auth.current_user(optional=True))):
        return {"auth": user is not None}

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


async def _expired_token(client) -> str:
    await _register(client)
    valid = (
        await client.post("/token", data={"username": "alice", "password": "pw123456"})
    ).json()["access_token"]
    payload = verify_token(valid, SECRET, TokenType.ACCESS)
    assert payload is not None
    return create_access_token({"sub": payload["sub"]}, SECRET, expires_delta=timedelta(seconds=-1))


async def test_expired_token_is_anonymous_under_optional(client) -> None:
    # expiry is the normal steady state, not an attack: optional auth treats it
    # as anonymous (200) rather than hard-failing (401).
    expired = await _expired_token(client)
    r = await client.get("/v1/maybe", headers={"Authorization": f"Bearer {expired}"})
    assert r.status_code == 200
    assert r.json() == {"auth": False}


async def test_expired_token_on_required_route_401(client) -> None:
    # required route still 401s (no other credential), but as "not authenticated"
    # after falling through - not a tampered-credential hard-fail.
    expired = await _expired_token(client)
    r = await client.get("/v1/items", headers={"Authorization": f"Bearer {expired}"})
    assert r.status_code == 401


async def test_tampered_token_still_hard_fails_under_optional(client) -> None:
    # a tampered token is an attack signal and hard-fails even under optional.
    await _register(client)
    r = await client.get("/v1/maybe", headers={"Authorization": "Bearer garbage"})
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


async def test_ungrantable_scope_is_clamped_out(client) -> None:
    # a scope outside grantable_scopes is silently dropped, not self-granted
    await _register(client)
    r = await client.post(
        "/token", data={"username": "alice", "password": "pw123456", "scope": "admin"}
    )
    token = r.json()["access_token"]
    payload = verify_token(token, SECRET, TokenType.ACCESS)
    assert payload is not None
    assert "admin" not in payload.get("scopes", [])


async def test_self_granted_scope_does_not_satisfy_gate(client) -> None:
    # requesting reports:read works (it's grantable); requesting admin does not
    # let the holder reach an admin-gated route - it's clamped out.
    await _register(client)
    r = await client.post(
        "/token", data={"username": "alice", "password": "pw123456", "scope": "admin reports:read"}
    )
    token = r.json()["access_token"]
    payload = verify_token(token, SECRET, TokenType.ACCESS)
    assert payload is not None
    assert set(payload.get("scopes", [])) == {"reports:read"}  # admin dropped, reports:read kept


def test_default_scopes_must_be_subset_of_grantable() -> None:
    with pytest.raises(ValueError, match="subset"):
        BearerTransport(default_scopes=["admin"], grantable_scopes=["reports:read"])


async def test_refresh_cookie_path_scopes_the_cookie(get_session, UserModel) -> None:
    # refresh_cookie_path narrows the refresh cookie to the refresh endpoint
    # rather than riding every request at "/".
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[
            BearerTransport(
                refresh="cookie",
                refresh_cookie_path="/auth/refresh",
                cookies=CookieConfig(secure=False),
            )
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
        r = await c.post("/token", data={"username": "alice", "password": "pw123456"})
        set_cookie = " ".join(r.headers.get_list("set-cookie"))
        assert "refresh_token=" in set_cookie
        assert "Path=/auth/refresh" in set_cookie
    await auth.shutdown()


class _Capture(EmailSender):
    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def send(
        self, *, to: str, subject: str, body: str, kind: str, context: EmailContext
    ) -> None:
        self.sent.append({"body": body, "kind": kind})

    def token_for(self, kind: str) -> str:
        for msg in reversed(self.sent):
            if msg["kind"] == kind:
                return msg["body"].split("token=")[-1]
        raise AssertionError(f"no {kind} email captured")


async def test_password_reset_revokes_outstanding_bearer_tokens(get_session, UserModel) -> None:
    sender = _Capture()
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[BearerTransport(refresh="body", cookies=CookieConfig(secure=False))],
        email=EmailConfig(sender=sender, frontend_url="https://app"),
    )
    app = FastAPI()
    app.include_router(auth.router)

    @app.get("/v1/items")
    async def items(user: Principal = Depends(auth.current_user(transport="bearer"))):
        return {"id": user.user_id}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        await c.post(
            "/register", json={"email": "a@x.com", "username": "alice", "password": "pw123456"}
        )
        tok = (await c.post("/token", data={"username": "alice", "password": "pw123456"})).json()
        access1, refresh1 = tok["access_token"], tok["refresh_token"]

        # both work before the reset
        assert (
            await c.get("/v1/items", headers={"Authorization": f"Bearer {access1}"})
        ).status_code == 200

        await c.post("/password/reset-request", json={"email": "a@x.com"})
        reset = sender.token_for("reset_password")
        assert (
            await c.post(
                "/password/reset-confirm", json={"token": reset, "new_password": "newpw12345"}
            )
        ).status_code == 200

        # the reset bumped token_version → the old access token's ver is now stale
        assert (
            await c.get("/v1/items", headers={"Authorization": f"Bearer {access1}"})
        ).status_code == 401
        # ...and the old refresh token can no longer mint access tokens
        assert (await c.post("/refresh", json={"refresh_token": refresh1})).status_code == 401

        # a fresh login carries the new ver and works
        tok2 = (await c.post("/token", data={"username": "alice", "password": "newpw12345"})).json()
        assert (
            await c.get("/v1/items", headers={"Authorization": f"Bearer {tok2['access_token']}"})
        ).status_code == 200
    await auth.shutdown()


async def test_refresh_reclamps_after_grantable_tightened(get_session, UserModel) -> None:
    # An outstanding refresh token carries scope "b"; after the operator removes
    # "b" from grantable_scopes, /refresh must stop minting it.
    bearer = BearerTransport(
        refresh="body",
        default_scopes=["a", "b"],
        grantable_scopes=["a", "b"],
        cookies=CookieConfig(secure=False),
    )
    auth = CRUDAuth(
        session=get_session, user_model=UserModel, SECRET_KEY=SECRET, transports=[bearer]
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
        tok = await c.post("/token", data={"username": "alice", "password": "pw123456"})
        refresh = tok.json()["refresh_token"]

        bearer.grantable_scopes = frozenset({"a"})  # operator tightens the ceiling

        r = await c.post("/refresh", json={"refresh_token": refresh})
        payload = verify_token(r.json()["access_token"], SECRET, TokenType.ACCESS)
        assert payload is not None
        assert set(payload.get("scopes", [])) == {"a"}  # "b" no longer grantable → dropped
    await auth.shutdown()


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
