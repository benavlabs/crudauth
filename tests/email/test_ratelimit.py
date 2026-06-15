"""Email-flow rate limiting (per-IP edge + silent per-email), input validation,
and the session SameSite=None rejection."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI

from crudauth import (
    AuthHooks,
    BearerTransport,
    CookieConfig,
    CRUDAuth,
    EmailConfig,
    EmailSender,
    SessionTransport,
)
from crudauth.email.service import EmailFlowService
from crudauth.ratelimit import MemoryRateLimiterBackend, RateLimit
from crudauth.repository import UserRepository
from crudauth.utils import get_password_hash


class Capture(EmailSender):
    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def send(self, *, to: str, subject: str, body: str, kind: str) -> None:
        self.sent.append({"to": to, "kind": kind})


# =============================================================================
# Silent per-target-email limit (service-level; preserves non-enumeration)
# =============================================================================
async def test_per_email_limit_is_silent(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        await repo.create(
            db, {"email": "v@x.com", "username": "v", "hashed_password": get_password_hash("pw")}
        )

    sender = Capture()
    svc = EmailFlowService(
        repo=repo,
        secret_key="test-secret-key-0123456789-0123456789",
        config=EmailConfig(sender=sender, frontend_url="https://app"),
        hooks=AuthHooks(),
        rate_limiter=MemoryRateLimiterBackend(),
        rate_limits={"password_reset_request": RateLimit(1, 3600)},
    )
    async with sessionmaker() as db:
        await svc.request_password_reset(db, "v@x.com")  # 1st: sends
        await svc.request_password_reset(db, "v@x.com")  # 2nd: over per-email cap → silent
    # no exception raised, and only one email went out
    assert len(sender.sent) == 1


async def test_existing_account_notice_is_throttled(UserModel) -> None:
    # the register "you already have an account" notice is silently per-target
    # throttled too, so a register-spray can't email-bomb a victim's address.
    sender = Capture()
    svc = EmailFlowService(
        repo=UserRepository(UserModel),
        secret_key="test-secret-key-0123456789-0123456789",
        config=EmailConfig(sender=sender, frontend_url="https://app"),
        hooks=AuthHooks(),
        rate_limiter=MemoryRateLimiterBackend(),
        rate_limits={"existing_account_notice": RateLimit(1, 3600)},
    )
    await svc.notify_existing_account("v@x.com")  # 1st: sends
    await svc.notify_existing_account("v@x.com")  # 2nd: over cap → silent no-op
    assert len(sender.sent) == 1


# =============================================================================
# Per-IP edge limit on a trigger endpoint (raises 429)
# =============================================================================
@pytest.fixture
async def email_client(get_session, UserModel) -> AsyncIterator[httpx.AsyncClient]:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        email=EmailConfig(sender=Capture(), frontend_url="https://app"),
        rate_limits={"password_reset_request": RateLimit(2, 3600)},
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c
    await auth.shutdown()


async def test_email_trigger_is_rate_limited(email_client) -> None:
    ok1 = await email_client.post("/password/reset-request", json={"email": "a@x.com"})
    ok2 = await email_client.post("/password/reset-request", json={"email": "b@x.com"})
    tripped = await email_client.post("/password/reset-request", json={"email": "c@x.com"})
    assert ok1.status_code == 200
    assert ok2.status_code == 200
    assert tripped.status_code == 429


async def test_reset_rejects_short_password(email_client) -> None:
    r = await email_client.post(
        "/password/reset-confirm", json={"token": "whatever", "new_password": "short"}
    )
    assert r.status_code == 422  # below MIN_PASSWORD_LENGTH


async def test_register_rejects_invalid_email(get_session, UserModel) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        r = await c.post(
            "/register", json={"email": "not-an-email", "username": "u", "password": "pw123456"}
        )
        assert r.status_code == 422
    await auth.shutdown()


async def test_register_rejects_short_password(get_session, UserModel) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        r = await c.post(
            "/register", json={"email": "a@x.com", "username": "u", "password": "short"}
        )
        assert r.status_code == 422  # below MIN_PASSWORD_LENGTH, like the reset flow
    await auth.shutdown()


# =============================================================================
# session transport rejects SameSite=None at construction
# =============================================================================
def test_session_rejects_samesite_none(get_session, UserModel) -> None:
    with pytest.raises(ValueError, match="SameSite=None"):
        CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY="test-secret-key-0123456789-0123456789",
            transports=[SessionTransport(cookies=CookieConfig(secure=True, samesite="none"))],
        )


def test_bearer_allows_samesite_none(get_session, UserModel) -> None:
    # bearer has no CSRF surface → SameSite=None is allowed (no raise)
    CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[BearerTransport(cookies=CookieConfig(secure=True, samesite="none"))],
    )
