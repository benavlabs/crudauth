"""Pluggable delivery channels: multi-channel best-effort, per-channel isolation,
the non-enumeration contract held across N channels, and channels-only apps."""

from __future__ import annotations

import httpx
from fastapi import FastAPI

from crudauth import (
    AuthHooks,
    CookieConfig,
    CRUDAuth,
    DeliveryChannel,
    DeliveryIntent,
    EmailConfig,
    EmailSender,
    SessionTransport,
)
from crudauth.constants import DEFAULT_RESET_TTL_HOURS, SECONDS_PER_HOUR
from crudauth.email.service import EmailFlowService
from crudauth.repository import UserRepository
from crudauth.utils import get_password_hash

SECRET = "test-secret-key-0123456789-0123456789"


class RecordingChannel(DeliveryChannel):
    def __init__(self) -> None:
        self.intents: list[DeliveryIntent] = []

    async def deliver(self, intent: DeliveryIntent, db) -> None:
        self.intents.append(intent)


class BoomChannel(DeliveryChannel):
    async def deliver(self, intent: DeliveryIntent, db) -> None:
        raise RuntimeError("channel down")


class CapturingSender(EmailSender):
    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def send(self, *, to, subject, body, kind, context) -> None:
        self.sent.append(
            {"to": to, "subject": subject, "body": body, "kind": kind, "context": context}
        )


async def _make_user(repo, sessionmaker, email="real@x.com") -> None:
    async with sessionmaker() as db:
        await repo.create(
            db,
            {
                "email": email,
                "username": email.split("@")[0],
                "hashed_password": get_password_hash("pw"),
            },
        )


def _service(UserModel, **kwargs) -> EmailFlowService:
    return EmailFlowService(
        repo=UserRepository(UserModel), secret_key=SECRET, hooks=AuthHooks(), **kwargs
    )


# --- security-critical: the non-enumeration contract across N channels ----


async def test_raising_channel_does_not_surface(sessionmaker, UserModel) -> None:
    # An existing user with a failing channel must not 500 (would be an oracle);
    # absent user returns early. Both complete without raising.
    repo = UserRepository(UserModel)
    await _make_user(repo, sessionmaker)
    svc = _service(UserModel, channels=[BoomChannel()])
    async with sessionmaker() as db:
        await svc.request_password_reset(db, "real@x.com")  # channel raises internally
        await svc.request_password_reset(db, "ghost@x.com")  # absent: early return


async def test_one_channel_failure_does_not_stop_another(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel)
    await _make_user(repo, sessionmaker)
    rec = RecordingChannel()
    svc = _service(UserModel, channels=[BoomChannel(), rec])
    async with sessionmaker() as db:
        await svc.request_password_reset(db, "real@x.com")
    assert len(rec.intents) == 1  # the second channel still fired
    assert rec.intents[0].kind == "reset_password"
    assert rec.intents[0].token is not None


async def test_absent_user_fires_no_channel(sessionmaker, UserModel) -> None:
    rec = RecordingChannel()
    svc = _service(UserModel, channels=[rec])
    async with sessionmaker() as db:
        await svc.request_password_reset(db, "ghost@x.com")
    assert rec.intents == []  # early-return preserved


# --- multi-channel + channels-only ----------------------------------------


async def test_email_and_extra_channel_both_receive(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel)
    await _make_user(repo, sessionmaker)
    sender = CapturingSender()
    rec = RecordingChannel()
    svc = _service(
        UserModel,
        config=EmailConfig(sender=sender, frontend_url="https://app"),
        channels=[rec],
    )
    async with sessionmaker() as db:
        await svc.request_password_reset(db, "real@x.com")
    assert [m["kind"] for m in sender.sent] == ["reset_password"]  # email channel
    assert [i.kind for i in rec.intents] == ["reset_password"]  # extra channel


async def test_channels_only_endpoints_mount_and_fire(get_session, UserModel, sessionmaker) -> None:
    # No EmailConfig at all: recovery endpoints still exist and the channel fires,
    # with token lifetimes falling back to the package defaults.
    rec = RecordingChannel()
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        channels=[rec],
    )
    await _make_user(UserRepository(UserModel), sessionmaker, email="reset@x.com")
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        r = await c.post("/password/reset-request", json={"email": "reset@x.com"})
        assert r.status_code == 200
    await auth.shutdown()
    assert len(rec.intents) == 1
    assert rec.intents[0].kind == "reset_password"
    assert rec.intents[0].expires_in == DEFAULT_RESET_TTL_HOURS * SECONDS_PER_HOUR


async def test_channel_can_load_app_column_via_db(sessionmaker, UserModel) -> None:
    # The actionable flows carry a live session, so a channel can re-load an app
    # column not in the contract dict (here full_name; for a real SMS channel, phone).
    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        await repo.create(
            db,
            {
                "email": "n@x.com",
                "username": "n",
                "hashed_password": get_password_hash("pw"),
                "full_name": "Ned",
            },
        )

    loaded: list[str] = []

    class NameChannel(DeliveryChannel):
        async def deliver(self, intent: DeliveryIntent, db) -> None:
            assert db is not None
            row = await db.get(UserModel, intent.user["id"])
            assert row is not None
            loaded.append(row.full_name)

    svc = _service(UserModel, channels=[NameChannel()])
    async with sessionmaker() as db:
        await svc.request_password_reset(db, "n@x.com")
    assert loaded == ["Ned"]


async def test_config_seeds_flow_ttls(sessionmaker, UserModel) -> None:
    # A NON-default EmailConfig TTL must flow through to the intent (the back-compat
    # seeding path), distinct from the package default - so this would fail if
    # _resolve_ttl ignored config and fell through to the default.
    repo = UserRepository(UserModel)
    await _make_user(repo, sessionmaker, email="t@x.com")
    rec = RecordingChannel()
    svc = _service(
        UserModel,
        config=EmailConfig(sender=CapturingSender(), frontend_url="https://app", reset_ttl_hours=2),
        channels=[rec],
    )
    async with sessionmaker() as db:
        await svc.request_password_reset(db, "t@x.com")
    assert rec.intents[0].expires_in == 2 * SECONDS_PER_HOUR
    assert 2 != DEFAULT_RESET_TTL_HOURS  # guards the test itself: 2 is non-default


async def test_existing_account_notice_passes_no_db(UserModel) -> None:
    # notify_existing_account has no session, so the notice intent is delivered
    # with db=None (the actionable flows get a real session; this one doesn't).
    class DbChannel(DeliveryChannel):
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        async def deliver(self, intent: DeliveryIntent, db) -> None:
            self.calls.append((intent.kind, db))

    ch = DbChannel()
    svc = _service(UserModel, channels=[ch])
    await svc.notify_existing_account("v@x.com")
    assert ch.calls == [("existing_account", None)]


async def test_facade_fires_email_and_channels_together(
    get_session, UserModel, sessionmaker
) -> None:
    # Through the mounted endpoint with BOTH email and an extra channel configured,
    # both fire (proves the facade gate + _build_email pass both into the service).
    sender = CapturingSender()
    rec = RecordingChannel()
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        email=EmailConfig(sender=sender, frontend_url="https://app"),
        channels=[rec],
    )
    await _make_user(UserRepository(UserModel), sessionmaker, email="both@x.com")
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        r = await c.post("/password/reset-request", json={"email": "both@x.com"})
        assert r.status_code == 200
    await auth.shutdown()
    assert [m["kind"] for m in sender.sent] == ["reset_password"]  # email channel
    assert [i.kind for i in rec.intents] == ["reset_password"]  # extra channel


# --- intent shape per kind -------------------------------------------------


async def test_intent_shapes_per_kind(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel)
    await _make_user(repo, sessionmaker, email="u@x.com")
    rec = RecordingChannel()
    svc = _service(
        UserModel, channels=[rec], verify_ttl_hours=24, reset_ttl_hours=1, change_ttl_hours=12
    )
    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "u@x.com")
        await svc.request_recovery_verification(db, "u@x.com")
        await svc.request_password_reset(db, "u@x.com")
        await svc.request_email_change(db, user, "new@x.com", "pw")
        await svc.notify_existing_account("u@x.com")

    by_kind = {i.kind: i for i in rec.intents}

    assert by_kind["verify_email"].token is not None
    assert by_kind["verify_email"].expires_in == 24 * SECONDS_PER_HOUR
    assert by_kind["reset_password"].token is not None
    assert by_kind["reset_password"].expires_in == 1 * SECONDS_PER_HOUR
    # change routes to the NEW address, not the current one
    assert by_kind["change_email"].recipient == "new@x.com"
    assert by_kind["change_email"].expires_in == 12 * SECONDS_PER_HOUR
    # the existing-account notice carries no token and no expiry
    assert by_kind["existing_account"].token is None
    assert by_kind["existing_account"].expires_in == 0
