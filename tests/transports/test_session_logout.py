"""Logging out from a route the app writes itself, and the session the logout hook names."""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import Depends, FastAPI, Request, Response

from crudauth import AuthHooks, CookieConfig, CRUDAuth, SessionTransport
from crudauth.repository import UserRepository
from crudauth.utils import get_password_hash

SECRET = "test-secret-key-0123456789-0123456789"
PASSWORD = "logout-pass-1"


def _app(
    get_session: Any, UserModel: Any, events: list[tuple[str, Any]]
) -> tuple[CRUDAuth, FastAPI]:
    transport = SessionTransport(cookies=CookieConfig(secure=False))

    async def logged_in(user: dict, *, request: Any, context: Any) -> None:
        events.append(("login", context.session_handle))

    async def logged_out(user: dict, *, request: Any, context: Any) -> None:
        events.append(("logout", context.session_handle))

    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[transport],
        hooks=AuthHooks(on_after_login=logged_in, on_after_logout=logged_out),
    )
    app = FastAPI()
    app.include_router(auth.router)

    @app.post("/admin/logout")
    async def admin_logout(
        request: Request, response: Response, db: Any = Depends(get_session)
    ) -> dict[str, bool]:
        return {"ended": await transport.complete_logout(request, response, db)}

    return auth, app


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def _user(sessionmaker: Any, UserModel: Any) -> None:
    async with sessionmaker() as db:
        await UserRepository(UserModel).create(
            db,
            {
                "email": "out@x.com",
                "username": "out",
                "hashed_password": get_password_hash(PASSWORD),
                "email_verified": True,
            },
        )


async def _login(client: httpx.AsyncClient) -> str:
    response = await client.post("/login", data={"username": "out", "password": PASSWORD})
    assert response.status_code == 200
    return str(response.json()["csrf_token"])


async def test_an_app_route_ends_the_session_and_the_hook_names_it(
    get_session: Any, UserModel: Any, sessionmaker: Any
) -> None:
    events: list[tuple[str, Any]] = []
    _, app = _app(get_session, UserModel, events)
    await _user(sessionmaker, UserModel)

    async with _client(app) as browser:
        csrf = await _login(browser)
        response = await browser.post("/admin/logout", headers={"X-CSRF-Token": csrf})
        cleared = browser.cookies.get("session_id") is None
        browser.cookies.clear()
        me = await browser.get("/me")

    assert response.json() == {"ended": True}
    assert cleared
    assert me.status_code == 401
    [(_, created), (_, ended)] = events
    assert [kind for kind, _ in events] == ["login", "logout"]
    assert ended is not None and ended == created


async def test_the_built_in_logout_names_the_session_too(
    get_session: Any, UserModel: Any, sessionmaker: Any
) -> None:
    events: list[tuple[str, Any]] = []
    _, app = _app(get_session, UserModel, events)
    await _user(sessionmaker, UserModel)

    async with _client(app) as browser:
        csrf = await _login(browser)
        assert (await browser.post("/logout", headers={"X-CSRF-Token": csrf})).status_code == 200

    assert events[1] == ("logout", events[0][1])
    assert events[0][1] is not None


async def test_a_live_session_without_the_csrf_header_is_not_ended(
    get_session: Any, UserModel: Any, sessionmaker: Any
) -> None:
    events: list[tuple[str, Any]] = []
    _, app = _app(get_session, UserModel, events)
    await _user(sessionmaker, UserModel)

    async with _client(app) as browser:
        await _login(browser)
        response = await browser.post("/admin/logout")
        me = await browser.get("/me")

    assert response.status_code == 403
    assert me.status_code == 200
    assert [kind for kind, _ in events] == ["login"]


async def test_without_a_session_there_is_nothing_to_end_and_no_hook(
    get_session: Any, UserModel: Any
) -> None:
    events: list[tuple[str, Any]] = []
    _, app = _app(get_session, UserModel, events)

    async with _client(app) as browser:
        browser.cookies.set("session_id", "not-a-session", domain="test.local")
        response = await browser.post("/admin/logout")
        cleared = browser.cookies.get("session_id") is None

    assert response.status_code == 200
    assert response.json() == {"ended": False}
    assert cleared
    assert events == []
