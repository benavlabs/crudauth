"""One cookie policy: session and bearer agree on secure/samesite."""

from __future__ import annotations

import httpx
from fastapi import FastAPI

from crudauth import BearerTransport, CookieConfig, CRUDAuth, SessionTransport


def _cookie_attr(response, name, attr) -> str | None:
    for header in response.headers.get_list("set-cookie"):
        if header.startswith(f"{name}="):
            for part in header.split(";"):
                k, _, v = part.strip().partition("=")
                if k.lower() == attr.lower():
                    return v or "true"
    return None


async def _app(get_session, UserModel, **kwargs):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        **kwargs,
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    return auth, app


async def test_both_transports_share_app_cookie_policy(get_session, UserModel) -> None:
    """A single app-wide CookieConfig governs BOTH the session cookie and the
    bearer refresh cookie - they can't silently disagree on samesite."""
    auth, app = await _app(
        get_session,
        UserModel,
        transports=[SessionTransport(), BearerTransport(refresh="cookie")],
        cookies=CookieConfig(secure=False, samesite="strict"),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        await c.post(
            "/register", json={"email": "a@x.com", "username": "a", "password": "pw123456"}
        )
        login = await c.post("/login", data={"username": "a", "password": "pw123456"})
        token = await c.post("/token", data={"username": "a", "password": "pw123456"})

    # session cookie honors the app policy
    assert _cookie_attr(login, "session_id", "samesite") == "strict"
    # bearer refresh cookie honors the SAME policy (no hardcoded "lax")
    assert _cookie_attr(token, "refresh_token", "samesite") == "strict"
    # secure=False respected on both (not present means not secure)
    assert _cookie_attr(login, "session_id", "secure") is None
    assert _cookie_attr(token, "refresh_token", "secure") is None
    await auth.shutdown()


async def test_per_transport_override(get_session, UserModel) -> None:
    """A transport handed its own CookieConfig overrides the app-wide default."""
    auth, app = await _app(
        get_session,
        UserModel,
        transports=[
            SessionTransport(),  # inherits app-wide (strict)
            BearerTransport(refresh="cookie", cookies=CookieConfig(secure=False, samesite="none")),
        ],
        cookies=CookieConfig(secure=False, samesite="strict"),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        await c.post(
            "/register", json={"email": "a@x.com", "username": "a", "password": "pw123456"}
        )
        login = await c.post("/login", data={"username": "a", "password": "pw123456"})
        token = await c.post("/token", data={"username": "a", "password": "pw123456"})

    assert _cookie_attr(login, "session_id", "samesite") == "strict"  # app-wide
    assert _cookie_attr(token, "refresh_token", "samesite") == "none"  # overridden
    await auth.shutdown()
