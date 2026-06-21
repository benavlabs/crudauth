"""Delivery channels: route a recovery token over a medium (email is built in).

crudauth owns the token (mint, one-time-use, redemption); a [DeliveryChannel]
[crudauth.email.channel.DeliveryChannel] owns the medium and the copy. The
recovery flows hand each configured channel a [DeliveryIntent]
[crudauth.email.channel.DeliveryIntent] and fire them all best-effort, so an app
can route reset/verify over email, SMS, WhatsApp, push, or several at once.
[EmailChannel][crudauth.email.channel.EmailChannel] is the built-in one.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .config import EmailConfig
from .constants import (
    SUBJECT_CHANGE,
    SUBJECT_EXISTING_ACCOUNT,
    SUBJECT_RESET,
    SUBJECT_VERIFY,
    EmailKind,
)
from .sender import EmailContext

if TYPE_CHECKING:  # pragma: no cover
    from sqlalchemy.ext.asyncio import AsyncSession

__all__ = ["DeliveryKind", "DeliveryIntent", "DeliveryChannel", "EmailChannel"]

# The channel-facing name for the message kind. Aliased to EmailKind so there is
# one source of truth for the values, no translation layer.
DeliveryKind = EmailKind


@dataclass(frozen=True)
class DeliveryIntent:
    """A recovery message crudauth needs delivered.

    crudauth owns the token and its lifetime; the channel owns the medium and the
    copy. Read what you need off ``recipient`` / ``user``; do not assume email.

    Attributes:
        kind: Which message this is (``verify_email`` for an email-recovery verify,
            ``verify_recovery`` for any other factor, ``reset_password`` /
            ``change_email`` / ``existing_account``). A non-email channel branches on
            this to pick its own medium-appropriate copy.
        token: The signed token, or ``None`` for ``existing_account`` (a notice
            with no action).
        user: The logical-contract user dict (``repo.to_dict``); empty for the
            ``existing_account`` notice. Contract fields only, so an app column
            (``phone``, ``whatsapp_id``, ...) is NOT here - load it off the ``db``
            handed to [deliver][crudauth.email.channel.DeliveryChannel.deliver].
        recipient: The resolved recovery destination (the email today; for an
            email change, the NEW address). A non-email channel typically ignores
            this and loads its own destination off the user.
        expires_in: Token lifetime in seconds (``0`` when ``token`` is ``None``).
    """

    kind: DeliveryKind
    token: str | None
    user: dict[str, Any]
    recipient: str
    expires_in: int


class DeliveryChannel(ABC):
    """A medium crudauth routes a recovery message over.

    crudauth fires every configured channel best-effort and swallows failures per
    channel, so raise freely on failure (it never surfaces and never stops the
    next channel). Reliability (retry/queue) belongs inside a channel.

    Example:
        ```python
        class SMSChannel(DeliveryChannel):
            async def deliver(self, intent: DeliveryIntent, db) -> None:
                if intent.kind != "reset_password" or intent.token is None or db is None:
                    return
                user = await db.get(User, intent.user["id"])   # an app column
                if user and user.phone:
                    await sms.enqueue(to=user.phone, token=intent.token)  # hand off
        ```
    """

    @abstractmethod
    async def deliver(self, intent: DeliveryIntent, db: AsyncSession | None) -> None:
        """Route, render, and send ``intent``.

        Raise on failure (crudauth swallows per channel). Must not assume email;
        read ``intent.recipient`` / ``intent.user``.

        ``db`` is the request-scoped session for the actionable flows (verify /
        reset / change), or ``None`` for the ``existing_account`` notice. Use it
        to load an app column you need (e.g.
        ``await db.get(User, intent.user["id"])`` for a phone number). It must be
        used **synchronously** and never committed or captured for deferred work:
        it is closed when the request ends, so a queued job that kept it would use
        a dead session. Read what you need, then enqueue the actual delivery.
        """
        raise NotImplementedError


# kind -> (subject, EmailConfig path attribute, body prefix) for the link kinds.
_EMAIL_SPECS: dict[str, tuple[str, str, str]] = {
    "verify_email": (SUBJECT_VERIFY, "verify_path", "Verify your email:"),
    "verify_recovery": (SUBJECT_VERIFY, "verify_path", "Verify your email:"),
    "reset_password": (SUBJECT_RESET, "reset_path", "Reset your password:"),
    "change_email": (SUBJECT_CHANGE, "change_path", "Confirm your new email:"),
}


class EmailChannel(DeliveryChannel):
    """The built-in channel: renders crudauth's recovery copy and calls the
    [EmailSender][crudauth.email.sender.EmailSender].

    Behaviorally identical to the email delivery crudauth shipped before delivery
    was pluggable; the subject/body/link building lives here now.
    """

    def __init__(self, config: EmailConfig):
        self._config = config

    async def deliver(self, intent: DeliveryIntent, db: AsyncSession | None) -> None:
        cfg = self._config
        if intent.kind == "existing_account":
            await cfg.sender.send(
                to=intent.recipient,
                subject=SUBJECT_EXISTING_ACCOUNT,
                body=(
                    "Someone tried to register with this email. You already have an "
                    f"account - sign in or reset your password at {cfg.frontend_url}."
                ),
                kind="existing_account",
                context=EmailContext(
                    kind="existing_account", link=None, recipient=intent.recipient, expires_in=0
                ),
            )
            return
        subject, path_attr, prefix = _EMAIL_SPECS[intent.kind]
        assert intent.token is not None
        link = cfg.link(getattr(cfg, path_attr), intent.token)
        await cfg.sender.send(
            to=intent.recipient,
            subject=subject,
            body=f"{prefix} {link}",
            kind=intent.kind,
            # context.link is the SAME assembled URL as in body (one source), never the bare token.
            context=EmailContext(
                kind=intent.kind,
                link=link,
                recipient=intent.recipient,
                expires_in=intent.expires_in,
            ),
        )
