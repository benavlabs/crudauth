"""EmailContext: the sender-facing render data.

The security shape of this feature, asserted directly: the context carries the
assembled link (token embedded in the URL), never a bare token and never any
user-controlled field, so a sender that drops context values into HTML can't be
the XSS or credential-leak vector. `context.link` is the SAME URL that's in
`body` (one source, can't diverge), and a sender that ignores context produces
today's exact email (the back-compat anchor)."""

from __future__ import annotations

from dataclasses import fields

from crudauth import AuthHooks, DeliveryIntent, EmailConfig, EmailContext, EmailSender
from crudauth.email.channel import EmailChannel
from crudauth.email.service import EmailFlowService
from crudauth.repository import UserRepository
from crudauth.utils import get_password_hash

SECRET = "test-secret-key-0123456789-0123456789"
FRONTEND = "https://app.example.com"


class RecordingSender(EmailSender):
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def send(self, *, to, subject, body, kind, context) -> None:
        self.calls.append(
            {"to": to, "subject": subject, "body": body, "kind": kind, "context": context}
        )


def _channel(sender: EmailSender) -> EmailChannel:
    return EmailChannel(EmailConfig(sender=sender, frontend_url=FRONTEND))


# --- the security regression catch: context exposes only crudauth render data ---


def test_context_exposes_only_crudauth_owned_fields() -> None:
    # If someone later adds `username`/`email`/`token` to EmailContext for
    # convenience, this fails - that's the point. User data is a DeliveryChannel
    # concern; the bare token stays on DeliveryIntent.
    names = {f.name for f in fields(EmailContext)}
    assert names == {"kind", "link", "recipient", "expires_in"}
    assert "token" not in names
    assert not any(n in names for n in ("user", "username", "email"))


async def test_link_carries_the_token_so_the_context_need_not() -> None:
    # The credential reaches the sender only as part of the URL (which is what
    # gets emailed), never as a standalone field it could mishandle.
    sender = RecordingSender()
    await _channel(sender).deliver(
        DeliveryIntent(
            kind="verify_email", token="tok123", user={}, recipient="a@x.com", expires_in=3600
        ),
        db=None,
    )
    ctx = sender.calls[-1]["context"]
    assert isinstance(ctx, EmailContext)
    assert ctx.link is not None and "token=tok123" in ctx.link
    assert not hasattr(ctx, "token")


# --- single source: context.link is the same URL as in body ---


async def test_context_link_equals_body_link_and_body_unchanged() -> None:
    sender = RecordingSender()
    await _channel(sender).deliver(
        DeliveryIntent(
            kind="verify_email", token="tok123", user={}, recipient="a@x.com", expires_in=3600
        ),
        db=None,
    )
    call = sender.calls[-1]
    ctx = call["context"]
    assert ctx.link is not None and ctx.link in call["body"]
    # back-compat anchor: body is byte-identical to what shipped before context.
    assert call["body"] == f"Verify your email: {ctx.link}"
    assert ctx.recipient == "a@x.com" and ctx.expires_in == 3600


async def test_existing_account_context_has_no_link() -> None:
    sender = RecordingSender()
    await _channel(sender).deliver(
        DeliveryIntent(
            kind="existing_account", token=None, user={}, recipient="a@x.com", expires_in=0
        ),
        db=None,
    )
    ctx = sender.calls[-1]["context"]
    assert ctx.kind == "existing_account" and ctx.link is None and ctx.expires_in == 0


# --- non-enumeration unchanged: an absent account never reaches the sender ---


async def test_absent_account_never_invokes_the_sender(sessionmaker, UserModel) -> None:
    sender = RecordingSender()
    svc = EmailFlowService(
        repo=UserRepository(UserModel),
        secret_key=SECRET,
        hooks=AuthHooks(),
        config=EmailConfig(sender=sender, frontend_url=FRONTEND),
    )
    async with sessionmaker() as db:
        await svc.request_password_reset(db, "ghost@x.com")
    assert sender.calls == []


async def test_real_flow_passes_context_with_matching_link(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        await repo.create(
            db,
            {"email": "real@x.com", "username": "real", "hashed_password": get_password_hash("pw")},
        )
    sender = RecordingSender()
    svc = EmailFlowService(
        repo=repo,
        secret_key=SECRET,
        hooks=AuthHooks(),
        config=EmailConfig(sender=sender, frontend_url=FRONTEND),
    )
    async with sessionmaker() as db:
        await svc.request_password_reset(db, "real@x.com")
    call = sender.calls[-1]
    assert call["kind"] == "reset_password"
    assert call["context"].link is not None and call["context"].link in call["body"]
