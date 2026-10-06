"""Public request-level principal resolution."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from fastapi import Depends, FastAPI, Request

from crudauth import CookieConfig, CRUDAuth, Principal, SessionTransport
from crudauth.core import AuthContext, Transport
from crudauth.exceptions import UnauthorizedException
from crudauth.transports.bearer.transport import BearerTransport

SECRET = "test-secret-key-0123456789-0123456789"


async def test_middleware_resolution_is_cached_and_does_not_bypass_csrf(get_session, UserModel):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()
    app.include_router(auth.router)

    @app.middleware("http")
    async def resolve(request: Request, call_next):
        request.state.middleware_principal = await auth.resolve_principal(request)
        return await call_next(request)

    @app.post("/protected")
    async def protected(user: Principal = Depends(auth.current_user())):
        return {"via": user.transport}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        await client.post(
            "/register", json={"email": "a@x.com", "username": "alice", "password": "pw123456"}
        )
        login = await client.post("/login", data={"username": "alice", "password": "pw123456"})
        csrf = login.json()["csrf_token"]
        assert (await client.post("/protected")).status_code == 403
        response = await client.post("/protected", headers={"X-CSRF-Token": csrf})
        assert response.json() == {"via": "session"}
    await auth.shutdown()


async def test_invalid_credentials_are_anonymous(get_session, UserModel):
    auth = CRUDAuth(session=get_session, user_model=UserModel, SECRET_KEY=SECRET)
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"authorization", b"Bearer bad")],
        }
    )
    assert await auth.resolve_principal(request) is None


class CountingTransport(Transport):
    name = "counting"

    def __init__(self):
        self.calls = 0

    async def authenticate(self, request: Request, ctx: AuthContext) -> Principal | None:
        self.calls += 1
        if request.headers.get("x-auth") != "yes":
            raise UnauthorizedException("invalid")
        user = await ctx.resolve_user(1)
        if user is None:
            return None
        return ctx.build_principal(user_id=ctx.repo.user_id(user), user=user, transport=self.name)


async def test_public_resolution_shares_cache_with_dependency(get_session, UserModel):
    from crudauth.utils import get_password_hash

    transport = CountingTransport()
    auth = CRUDAuth(
        session=get_session, user_model=UserModel, SECRET_KEY=SECRET, transports=[transport]
    )
    app = FastAPI()

    @app.middleware("http")
    async def resolve(request: Request, call_next):
        await auth.resolve_principal(request)
        return await call_next(request)

    @app.get("/")
    async def route(user: Principal = Depends(auth.current_user())):
        return {"id": user.user_id}

    await auth.initialize()
    async for db in auth.session():
        u = UserModel(
            email="counting@test.com",
            username="counter",
            hashed_password=get_password_hash("pw123456"),
        )
        db.add(u)
        await db.commit()
        real_id = auth.repo.user_id(u)
        break

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/", headers={"X-Auth": "yes"})
        assert response.json() == {"id": real_id}
    await auth.shutdown()
    assert transport.calls == 1


async def test_tampered_bearer_rejected_by_optional_dependency(get_session, UserModel):
    """A tampered bearer token must raise 401 even when middleware has cached nothing."""
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[BearerTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()

    @app.middleware("http")
    async def resolve(request: Request, call_next):
        await auth.resolve_principal(request)
        return await call_next(request)

    @app.get("/maybe")
    async def maybe(user: Principal | None = Depends(auth.current_user(optional=True))):
        return {"auth": user is not None}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        r = await c.get("/maybe", headers={"Authorization": "Bearer tampered.token.value"})
    await auth.shutdown()
    assert r.status_code == 401


def _session_app_with_middleware(get_session, UserModel):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()
    app.include_router(auth.router)

    @app.middleware("http")
    async def resolve(request: Request, call_next):
        await auth.resolve_principal(request)
        return await call_next(request)

    return app, auth


async def _register_and_login(client) -> str:
    await client.post(
        "/register", json={"email": "a@x.com", "username": "alice", "password": "pw123456"}
    )
    login = await client.post("/login", data={"username": "alice", "password": "pw123456"})
    return login.json()["csrf_token"]


async def test_route_updates_session_activity_after_middleware_resolution(get_session, UserModel):
    app, auth = _session_app_with_middleware(get_session, UserModel)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        await _register_and_login(client)
        session_id = client.cookies.get("session_id")
        before = await auth.sessions.get_session(session_id)
        await asyncio.sleep(0.01)
        assert (await client.get("/me")).status_code == 200
        after = await auth.sessions.get_session(session_id)
    await auth.shutdown()
    assert after.last_activity > before.last_activity


async def test_route_can_update_user_after_middleware_resolution(get_session, UserModel):
    app, auth = _session_app_with_middleware(get_session, UserModel)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        csrf = await _register_and_login(client)
        changed = await client.post(
            "/change-password",
            json={"current_password": "pw123456", "new_password": "newpass123"},
            headers={"X-CSRF-Token": csrf},
        )
        relogin = await client.post("/login", data={"username": "alice", "password": "newpass123"})
    await auth.shutdown()
    assert changed.status_code == 200, changed.text
    assert relogin.status_code == 200


class RevalidatingTransport(Transport):
    name = "revalidating"

    def __init__(self, still_valid: bool):
        self.still_valid = still_valid
        self.revalidations: list[tuple[bool, bool]] = []

    async def authenticate(self, request: Request, ctx: AuthContext) -> Principal | None:
        if request.headers.get("x-auth") != "yes":
            return None
        user = await ctx.resolve_user(1)
        if user is None:
            return None
        return ctx.build_principal(user_id=ctx.repo.user_id(user), user=user, transport=self.name)

    async def revalidate(self, request: Request, principal: Principal, ctx: AuthContext) -> bool:
        self.revalidations.append((ctx.enforce_csrf, ctx.update_activity))
        return self.still_valid


@pytest.mark.parametrize(("still_valid", "status"), [(True, 200), (False, 401)])
async def test_route_revalidates_principal_resolved_in_middleware(
    get_session, UserModel, still_valid, status
):
    from crudauth.utils import get_password_hash

    transport = RevalidatingTransport(still_valid)
    auth = CRUDAuth(
        session=get_session, user_model=UserModel, SECRET_KEY=SECRET, transports=[transport]
    )
    app = FastAPI()

    @app.middleware("http")
    async def resolve(request: Request, call_next):
        await auth.resolve_principal(request)
        return await call_next(request)

    @app.post("/")
    async def route(user: Principal = Depends(auth.current_user())):
        return {"id": user.user_id}

    await auth.initialize()
    async for db in auth.session():
        db.add(
            UserModel(
                email="revalidate@test.com",
                username="revalidator",
                hashed_password=get_password_hash("pw123456"),
            )
        )
        await db.commit()
        break

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/", headers={"X-Auth": "yes"})
    await auth.shutdown()
    assert response.status_code == status
    assert transport.revalidations == [(True, True)]
