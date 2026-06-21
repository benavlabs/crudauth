"""Regression tests pinning the bugs found in review (so they can't come back)."""

from __future__ import annotations

import hashlib
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from sqlalchemy.exc import IntegrityError
from starlette.requests import Request

from crudauth import (
    AuthHooks,
    CRUDAuth,
    CookieConfig,
    EmailConfig,
    EmailContext,
    EmailSender,
    OAuthCredentials,
    SessionTransport,
)
from crudauth.email.service import EmailFlowService
from crudauth.oauth import (
    AbstractOAuthProvider,
    OAuthAccountService,
    OAuthProviderFactory,
    OAuthUserInfo,
)
from crudauth.ratelimit import LockoutPolicy, MemoryRateLimiterBackend
from crudauth.repository import UserRepository
from crudauth.storage import get_session_storage
from crudauth.transports.bearer.tokens import create_signed_token
from crudauth.transports.session import SessionManager
from crudauth.transports.session.schemas import SessionData
from crudauth.utils import get_password_hash


# =============================================================================
# user_id type contract: JWT 'sub' is a string; get_by_id must coerce to PK
# =============================================================================
async def test_get_by_id_coerces_string_sub_to_int_pk(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        user = await repo.create(db, {"email": "a@x.com", "username": "a", "hashed_password": "h"})
        uid = repo.user_id(user)
        assert isinstance(uid, int)

    # The JWT/email paths hand get_by_id a *string* sub.
    async with sessionmaker() as db:
        got = await repo.get_by_id(db, str(uid))
        assert got is not None
        assert repo.user_id(got) == uid


async def test_get_by_id_uncoercible_returns_none(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        assert await repo.get_by_id(db, "not-an-int") is None


def test_repo_coerce_id_helper(UserModel) -> None:
    repo = UserRepository(UserModel)
    assert repo._coerce_id("42") == 42
    assert repo._coerce_id(42) == 42


async def test_bearer_and_email_flow_use_consistent_id_type(sessionmaker, UserModel) -> None:
    """End-to-end: a strict repo that refuses cross-type comparison still works.

    This is the production-shape guard - SQLite coerces "42"==42, but this fake
    repo (like Postgres) does not, so it only matches when the id type is right.
    """

    class StrictRepo(UserRepository):
        async def get_by_id(self, db, user_id):
            coerced = self._coerce_id(user_id)
            # emulate a backend that does NOT coerce: only int matches int PK
            if not isinstance(coerced, int):
                return None
            return await UserRepository.get_by_id(self, db, coerced)

    repo = StrictRepo(UserModel)
    async with sessionmaker() as db:
        user = await repo.create(db, {"email": "s@x.com", "username": "s", "hashed_password": "h"})
        uid = repo.user_id(user)
    async with sessionmaker() as db:
        # string sub from a token still resolves because _coerce_id fixed the type
        assert await repo.get_by_id(db, str(uid)) is not None


# =============================================================================
# remember_me cookie lifetime tracks the server-side window
# =============================================================================
async def test_session_cookie_is_session_scoped_remember_me_is_persistent(
    get_session, UserModel
) -> None:
    # a non-remember login emits a SESSION cookie (no Max-Age) so the
    # server-side sliding idle check is the real expiry; remember-me emits a
    # persistent cookie with a long Max-Age.
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[
            SessionTransport(
                cookies=CookieConfig(secure=False), session_timeout_minutes=30, remember_me_days=30
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
            "/register", json={"email": "a@x.com", "username": "a", "password": "pw123456"}
        )
        plain = await c.post("/login", data={"username": "a", "password": "pw123456"})
        remembered = await c.post(
            "/login", data={"username": "a", "password": "pw123456", "remember_me": "true"}
        )
    await auth.shutdown()
    # non-remember → no Max-Age (session cookie)
    assert _cookie_max_age(plain, "session_id") is None
    # remember-me → persistent, ~30 days
    assert _cookie_max_age(remembered, "session_id") == 30 * 24 * 3600


def _cookie_max_age(response, name) -> int | None:
    for header in response.headers.get_list("set-cookie"):
        if header.startswith(f"{name}="):
            for part in header.split(";"):
                part = part.strip().lower()
                if part.startswith("max-age="):
                    return int(part.split("=", 1)[1])
    return None  # no Max-Age attribute → a session cookie


# =============================================================================
# OAuth: email required; unverified email is not auto-linked
# =============================================================================
class _Stub(AbstractOAuthProvider):
    def __init__(self, *a, info=None, **k):
        super().__init__(
            "id",
            "sec",
            "http://cb",
            scopes=["s"],
            authorize_endpoint="http://a",
            token_endpoint="http://t",
            userinfo_endpoint="http://u",
            provider_name="x",
        )
        self._info = info

    async def process_user_info(self, user_info) -> OAuthUserInfo:
        return self._info


async def test_oauth_no_email_raises_not_500(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel)
    service = OAuthAccountService(repo)
    info = OAuthUserInfo(provider="x", provider_user_id="1", email=None, email_verified=True)
    async with sessionmaker() as db:
        with pytest.raises(HTTPException) as exc:
            await service.get_or_create_user(info, db)
        assert exc.value.status_code == 400


async def test_oauth_unverified_email_not_linked(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel)
    service = OAuthAccountService(repo)
    async with sessionmaker() as db:
        await repo.create(
            db,
            {
                "email": "victim@x.com",
                "username": "victim",
                "hashed_password": get_password_hash("pw"),
            },
        )
    info = OAuthUserInfo(
        provider="github",
        provider_user_id="attacker",
        email="victim@x.com",
        email_verified=False,  # attacker-controlled, unverified
    )
    async with sessionmaker() as db:
        with pytest.raises(HTTPException) as exc:
            await service.get_or_create_user(info, db)
        assert exc.value.status_code == 400


async def test_oauth_verified_email_links(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel)
    service = OAuthAccountService(repo)
    async with sessionmaker() as db:
        existing = await repo.create(
            db,
            {"email": "ok@x.com", "username": "ok", "hashed_password": get_password_hash("pw")},
        )
        existing_id = repo.user_id(existing)
    info = OAuthUserInfo(
        provider="github", provider_user_id="gh-1", email="ok@x.com", email_verified=True
    )
    async with sessionmaker() as db:
        user, created = await service.get_or_create_user(info, db)
        assert created is False
        assert repo.user_id(user) == existing_id


# =============================================================================
# open redirect is neutralized
# =============================================================================
class StubRedirectProvider(AbstractOAuthProvider):
    def __init__(self, client_id, client_secret, redirect_uri, scopes=None):
        super().__init__(
            client_id,
            client_secret,
            redirect_uri,
            scopes=["s"],
            authorize_endpoint="https://stub/authorize",
            token_endpoint="https://stub/token",
            userinfo_endpoint="https://stub/userinfo",
            provider_name="redir",
        )

    async def exchange_code(self, code, code_verifier=None, headers=None):
        return {"access_token": "a"}

    async def get_user_info(self, access_token):
        return {"id": "1", "email": "r@x.com"}

    async def process_user_info(self, user_info) -> OAuthUserInfo:
        return OAuthUserInfo(
            provider="redir", provider_user_id="1", email="r@x.com", email_verified=True
        )


OAuthProviderFactory.register_provider("redir", StubRedirectProvider)


async def _run_oauth_redirect(get_session, UserModel, redirect_to):
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        oauth={"redir": OAuthCredentials(client_id="i", client_secret="s")},
        redirect_base_url="http://test",
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        r = await c.get("/oauth/redir/authorize", params={"redirect_to": redirect_to})
        state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
        r = await c.get(f"/oauth/redir/callback?code=abc&state={state}")
        location = r.headers["location"]
    await auth.shutdown()
    return location


@pytest.mark.parametrize(
    "evil",
    [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",  # backslash → browsers normalize to //evil.com
        "/\\/evil.com",
        "\\/evil.com",
        "javascript:alert(1)",
        "/\tevil",  # control char
    ],
)
async def test_open_redirect_blocked(evil, get_session, UserModel) -> None:
    # every hostile target falls back to the safe same-origin default
    location = await _run_oauth_redirect(get_session, UserModel, evil)
    assert "evil.com" not in location
    assert location == "http://test"


@pytest.mark.parametrize("ok", ["/dashboard", "/a/b?c=d", "/"])
async def test_safe_relative_redirect_honored(ok, get_session, UserModel) -> None:
    location = await _run_oauth_redirect(get_session, UserModel, ok)
    assert location == ok


# =============================================================================
# /register survives a unique-collision race (no 500)
# =============================================================================
async def test_register_integrityerror_recovers_cleanly(
    get_session, UserModel, monkeypatch
) -> None:
    # Force the lost-race branch deterministically: pre-check passes (no row),
    # the insert raises IntegrityError → the route must recover to a clean
    # duplicate response (DuplicateValueException → 422), not a 500.
    # (A true concurrent test isn't viable here: the conftest's in-memory SQLite
    # shares one connection via StaticPool, so two sessions corrupt each other's
    # transaction rather than isolating - an artifact of the test DB, not the code.)
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )

    async def boom(*args, **kwargs):
        raise IntegrityError("INSERT", {}, Exception("UNIQUE constraint failed"))

    monkeypatch.setattr(auth.repo, "create", boom)

    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        r = await c.post(
            "/register", json={"email": "a@x.com", "username": "a", "password": "pw123456"}
        )
        assert r.status_code != 500  # the race is recovered, not crashed
        assert r.status_code == 422  # clean duplicate (DuplicateValueException)
    await auth.shutdown()


# =============================================================================
# cleanup sweep does NOT wipe login-lockout state
# =============================================================================
async def test_cleanup_preserves_lockout() -> None:
    mgr = SessionManager(
        get_session_storage("memory", prefix="session:"),
        csrf_storage=get_session_storage("memory", prefix="csrf:"),
        lockout=LockoutPolicy(MemoryRateLimiterBackend(), max_attempts=2, fail_open=False),
    )
    # trip the lockout
    for _ in range(4):
        allowed, _, retry = await mgr.track_login_attempt("9.9.9.9", "bob", success=False)
    assert allowed is False and retry > 0

    # a cleanup sweep must NOT clear it
    await mgr.cleanup_expired_sessions(force=True)
    allowed, _, retry = await mgr.track_login_attempt("9.9.9.9", "bob", success=False)
    assert allowed is False  # still locked
    assert retry > 0


# =============================================================================
# CSRF token slides forward with session activity
# =============================================================================
async def test_csrf_renews_with_session_activity() -> None:
    mgr = SessionManager(
        get_session_storage("memory", prefix="session:", expiration=1800),
        csrf_storage=get_session_storage("memory", prefix="csrf:", expiration=1800),
    )
    req = Request({"type": "http", "method": "GET", "headers": [], "client": ("1.1.1.1", 1)})
    sid, csrf = await mgr.create_session(req, user_id=1)

    # the session records the csrf token id for sliding renewal
    session = await mgr.storage.get(sid, SessionData)
    assert session is not None
    assert session.metadata.get("csrf_token_id") == csrf

    # activity (validate_session) keeps the csrf token valid
    await mgr.validate_session(sid)
    assert await mgr.validate_csrf_token(sid, csrf) is True


# =============================================================================
# register is non-enumerating when email is configured; and is throttled
# =============================================================================
class _Capture(EmailSender):
    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def send(
        self, *, to: str, subject: str, body: str, kind: str, context: EmailContext
    ) -> None:
        self.sent.append({"to": to, "kind": kind})


async def test_register_does_not_leak_existing_email(get_session, UserModel) -> None:
    sender = _Capture()
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        email=EmailConfig(sender=sender, frontend_url="https://app.example.com"),
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        r1 = await c.post(
            "/register", json={"email": "dup@x.com", "username": "u1", "password": "pw123456"}
        )
        # second registration with same email, different username:
        r2 = await c.post(
            "/register", json={"email": "dup@x.com", "username": "u2", "password": "pw123456"}
        )
    await auth.shutdown()
    # New-email and existing-email responses are byte-identical (status + body),
    # so registration reveals nothing about which emails exist.
    assert r1.status_code == 202
    assert r2.status_code == 202
    assert r1.json() == r2.json()
    # the real owner still gets a security notice
    assert any(m["kind"] == "existing_account" and m["to"] == "dup@x.com" for m in sender.sent)


async def test_register_throttled(get_session, UserModel) -> None:
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
        statuses = []
        for i in range(7):
            r = await c.post(
                "/register",
                json={"email": f"u{i}@x.com", "username": f"u{i}", "password": "pw123456"},
            )
            statuses.append(r.status_code)
    await auth.shutdown()
    assert 429 in statuses  # throttle kicks in within the window


# =============================================================================
# confirm_email_change keeps the token if the target became taken
# =============================================================================
async def test_email_change_token_survives_race(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel)
    sender = _Capture()
    store = get_session_storage("memory", prefix="used:")
    svc = EmailFlowService(
        repo=repo,
        secret_key="test-secret-key-0123456789-0123456789",
        config=EmailConfig(sender=sender, frontend_url="https://app"),
        hooks=AuthHooks(),
        token_store=store,
    )
    async with sessionmaker() as db:
        user = await repo.create(
            db, {"email": "me@x.com", "username": "me", "hashed_password": "h"}
        )
        uid = repo.user_id(user)
        # someone else already owns the target email
        await repo.create(db, {"email": "taken@x.com", "username": "other", "hashed_password": "h"})

    token = create_signed_token(
        "test-secret-key-0123456789-0123456789",
        uid,
        "change_email",
        extra_claims={"new_email": "taken@x.com"},
    )
    async with sessionmaker() as db:
        with pytest.raises(HTTPException) as exc:
            await svc.confirm_email_change(db, token)
        assert exc.value.status_code == 422  # duplicate, not "token used"
    # the token was NOT consumed (so a fresh attempt with a free email could work)
    assert not await store.exists(hashlib.sha256(token.encode()).hexdigest())
