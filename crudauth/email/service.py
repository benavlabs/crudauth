"""Orchestrates verify / reset / change-email flows on top of signed tokens."""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..constants import (
    DEFAULT_ALGORITHM,
    DEFAULT_CHANGE_TTL_HOURS,
    DEFAULT_RESET_TTL_HOURS,
    DEFAULT_VERIFY_TTL_HOURS,
    SECONDS_PER_HOUR,
)
from ..exceptions import BadRequestException, DuplicateValueException
from ..hooks import AuthHooks, HookContext
from ..ratelimit import RateLimit
from ..repository import UserRepository
from ..storage.base import AbstractSessionStorage
from ..transports.bearer.tokens import (
    create_signed_token,
    verify_signed_token,
    verify_signed_token_full,
)
from ..utils import canonical_email, get_password_hash, verify_password
from .channel import DeliveryChannel, DeliveryIntent, EmailChannel
from .config import EmailConfig
from .constants import (
    CHANGE,
    CHANGE_ACTION,
    EXISTING_ACCOUNT_ACTION,
    RESET,
    RESET_ACTION,
    VERIFY,
    VERIFY_ACTION,
)

if TYPE_CHECKING:  # pragma: no cover
    from ..ratelimit import RateLimiterBackend
    from ..transports.session.manager import SessionManager

__all__ = ["EmailFlowService"]

logger = logging.getLogger("crudauth")


class _UsedToken(BaseModel):
    used: bool = True


class EmailFlowService:
    """Mints/verifies signed tokens and drives the recovery flows.

    The package owns token lifecycle; *delivery* is pluggable via one or more
    [DeliveryChannel][crudauth.email.channel.DeliveryChannel]s (email is the
    built-in one). Trigger endpoints are throttled two ways: a per-IP edge limit
    (in the router) and a **silent** per-target-email limit here - silent because
    a 429 on a victim's address would re-introduce the enumeration oracle and
    hand an attacker a DoS lever against that user.

    Construction is additive: pass ``config=EmailConfig(...)`` (back-compat, which
    builds an [EmailChannel][crudauth.email.channel.EmailChannel] and seeds the
    token TTLs) and/or ``channels=[...]`` plus explicit ``*_ttl_hours``.
    """

    def __init__(
        self,
        *,
        repo: UserRepository,
        secret_key: str,
        hooks: AuthHooks,
        config: EmailConfig | None = None,
        channels: list[DeliveryChannel] | None = None,
        algorithm: str = DEFAULT_ALGORITHM,
        token_store: AbstractSessionStorage[Any] | None = None,
        session_manager: "SessionManager | None" = None,
        rate_limiter: "RateLimiterBackend | None" = None,
        rate_limits: dict[str, RateLimit] | None = None,
        verify_ttl_hours: int | None = None,
        reset_ttl_hours: int | None = None,
        change_ttl_hours: int | None = None,
    ):
        self.repo = repo
        self.secret_key = secret_key
        self.hooks = hooks
        self.algorithm = algorithm
        self.token_store = token_store
        self.session_manager = session_manager
        self.rate_limiter = rate_limiter
        self.rate_limits = rate_limits or {}

        channel_list: list[DeliveryChannel] = []
        if config is not None:
            channel_list.append(EmailChannel(config))
        if channels:
            channel_list.extend(channels)
        self._channels = channel_list

        self.verify_ttl_hours = self._resolve_ttl(
            verify_ttl_hours, config, "verify_ttl_hours", DEFAULT_VERIFY_TTL_HOURS
        )
        self.reset_ttl_hours = self._resolve_ttl(
            reset_ttl_hours, config, "reset_ttl_hours", DEFAULT_RESET_TTL_HOURS
        )
        self.change_ttl_hours = self._resolve_ttl(
            change_ttl_hours, config, "change_ttl_hours", DEFAULT_CHANGE_TTL_HOURS
        )

    @staticmethod
    def _resolve_ttl(
        override: int | None, config: EmailConfig | None, attr: str, default: int
    ) -> int:
        """TTL precedence: explicit override, then the EmailConfig's value, then
        the package default. So a channels-only app still has token lifetimes."""
        if override is not None:
            return override
        if config is not None:
            return int(getattr(config, attr))
        return default

    async def _deliver(self, intent: DeliveryIntent, db: AsyncSession | None) -> None:
        """Fire every configured channel best-effort, forwarding the request ``db``.

        ``db`` is the request session (or ``None`` for the existing-account
        notice); each channel may read from it synchronously to load an app column.

        Per-channel isolation: the ``try`` is inside the loop, so one channel
        raising cannot stop the next (a dead WhatsApp integration must not
        suppress the email that recovers the account). Returns ``None`` regardless
        and surfaces nothing - the ``request_*`` response is identical whether the
        user existed or not, and there is deliberately no "at least one succeeded"
        accounting (observing success would reopen the enumeration oracle).
        """
        for channel in self._channels:
            try:
                await channel.deliver(intent, db)
            except Exception:
                logger.warning(
                    "crudauth: %s delivery via %s failed",
                    intent.kind,
                    type(channel).__name__,
                    exc_info=True,
                )

    # --- one-time-use guard --------------------------------------------------
    async def _consume(self, token: str, ttl_seconds: int) -> bool:
        """Mark a token consumed. Returns ``True`` on first use, ``False`` on replay.

        Uses the storage layer's atomic ``set_if_absent`` so two concurrent
        redemptions of the same token can't both win the race - which, for a
        password reset, could otherwise apply two different new passwords.
        """
        if self.token_store is None:
            return True
        key = hashlib.sha256(token.encode()).hexdigest()
        return await self.token_store.set_if_absent(key, _UsedToken(), expiration=ttl_seconds)

    async def _email_within_limit(self, action: str, email: str) -> bool:
        """Per-target-email throttle. Returns ``True`` if a send is allowed.

        Note:
            Keyed on the *canonical* address so a victim can't be email-bombed
            even from rotating IPs. Callers must treat a ``False`` result as a
            silent no-op (don't send, don't raise) to preserve non-enumeration.
        """
        if self.rate_limiter is None:
            return True
        limit = self.rate_limits.get(action)
        if limit is None or limit.disabled:
            return True
        _, limited, _ = await self.rate_limiter.increment_and_check(
            f"email:{action}:{canonical_email(email)}", limit.times, limit.seconds, fail_open=True
        )
        return not limited

    async def notify_existing_account(self, email: str) -> None:
        """Tell an existing owner someone tried to register with their email.

        Lets registration stay non-enumerable: the API responds identically
        whether or not the email was already taken, and the real owner gets a
        security heads-up.

        Note:
            Uses ``kind="existing_account"`` - a security notice, distinct from
            the ``welcome`` template, so the adapter doesn't render a cheery
            greeting to someone who already has an account.

        Note:
            Subject to the same silent per-target throttle as the other flows, so
            a register-spray (the per-IP limit is spoofable) can't email-bomb a
            victim's address. A throttled send is a silent no-op - the route
            still returns its uniform response, preserving non-enumeration.
        """
        if not await self._email_within_limit(EXISTING_ACCOUNT_ACTION, email):
            return
        await self._deliver(
            DeliveryIntent(
                kind="existing_account", token=None, user={}, recipient=email, expires_in=0
            ),
            None,
        )

    # --- recovery-factor verification ----------------------------------------
    async def request_recovery_verification(self, db: AsyncSession, value: str) -> None:
        """Send a verification token for the contract's recovery factor.

        Idempotent; never reveals account existence. The user is looked up by the
        recovery factor (email for email recovery, phone for phone recovery) and
        the token is delivered to that factor's value over the configured channel.
        """
        factor = self.repo.recovery
        if factor is None:
            return
        if not await self._email_within_limit(VERIFY_ACTION, value):
            return
        user = await self.repo.get_by_field(db, factor, value)
        if user is None or self.repo.recovery_verified(user):
            return
        token = create_signed_token(
            self.secret_key,
            self.repo.user_id(user),
            VERIFY,
            expires_hours=self.verify_ttl_hours,
            algorithm=self.algorithm,
        )
        await self._deliver(
            DeliveryIntent(
                kind="verify_email" if factor == "email" else "verify_recovery",
                token=token,
                user=self.repo.to_dict(user),
                recipient=self.repo.get(user, factor),
                expires_in=self.verify_ttl_hours * SECONDS_PER_HOUR,
            ),
            db,
        )

    async def confirm_recovery_verification(self, db: AsyncSession, token: str) -> Any:
        """Verify the signed token and mark the user's email verified (one-time-use).

        Args:
            db: Active async session.
            token: The signed verification token from the emailed link.

        Returns:
            The verified user row.

        Raises:
            BadRequestException: If the token is invalid, expired, or already used.
        """
        sub = verify_signed_token(token, self.secret_key, VERIFY, algorithm=self.algorithm)
        if sub is None:
            raise BadRequestException("Invalid or expired token")
        if not await self._consume(token, self.verify_ttl_hours * SECONDS_PER_HOUR):
            raise BadRequestException("Token already used")
        user = await self.repo.get_by_id(db, sub)
        if user is None:
            raise BadRequestException("Invalid or expired token")
        if not self.repo.recovery_verified(user):
            await self.repo.mark_recovery_verified(db, user)
            await self.hooks.run_after_recovery_verified(
                self.repo.to_dict(user), db=db, context=HookContext()
            )
        return user

    # --- password reset ------------------------------------------------------
    async def request_password_reset(self, db: AsyncSession, value: str) -> None:
        """Send a reset token over the configured channel. Idempotent; never reveals
        account existence. Looked up by, and delivered to, the recovery factor."""
        factor = self.repo.recovery
        if factor is None:
            return
        if not await self._email_within_limit(RESET_ACTION, value):
            return
        user = await self.repo.get_by_field(db, factor, value)
        if user is None:
            return
        token = create_signed_token(
            self.secret_key,
            self.repo.user_id(user),
            RESET,
            expires_hours=self.reset_ttl_hours,
            algorithm=self.algorithm,
        )
        await self._deliver(
            DeliveryIntent(
                kind="reset_password",
                token=token,
                user=self.repo.to_dict(user),
                recipient=self.repo.get(user, factor),
                expires_in=self.reset_ttl_hours * SECONDS_PER_HOUR,
            ),
            db,
        )

    async def reset_password(self, db: AsyncSession, token: str, new_password: str) -> Any:
        """Reset the password and evict every outstanding credential.

        Args:
            db: Active async session.
            token: The signed reset token from the emailed link.
            new_password: The new plaintext password (hashed before storage).

        Returns:
            The updated user row.

        Raises:
            BadRequestException: If the token is invalid, expired, or already used.

        Note:
            A reset is attacker-eviction: it often follows a compromise, so any
            credential an attacker holds must die with it. Server-side sessions
            are terminated, and the user's ``token_version`` is bumped - which
            invalidates all outstanding bearer access and refresh tokens (their
            ``ver`` claim is now stale). Bearer eviction needs a ``token_version``
            column; without it (a custom model that omits it) only sessions are
            evicted.
        """
        sub = verify_signed_token(token, self.secret_key, RESET, algorithm=self.algorithm)
        if sub is None:
            raise BadRequestException("Invalid or expired token")
        if not await self._consume(token, self.reset_ttl_hours * SECONDS_PER_HOUR):
            raise BadRequestException("Token already used")
        user = await self.repo.get_by_id(db, sub)
        if user is None:
            raise BadRequestException("Invalid or expired token")
        await self.repo.update(db, user, {"hashed_password": get_password_hash(new_password)})
        await self.repo.increment_token_version(db, user)
        if self.session_manager is not None:
            await self.session_manager.terminate_all_user_sessions(
                self.repo.user_id(user), reason="password_reset"
            )
        await self.hooks.run_after_password_reset(
            self.repo.to_dict(user), db=db, context=HookContext()
        )
        return user

    # --- email change --------------------------------------------------------
    async def request_email_change(
        self, db: AsyncSession, user: Any, new_email: str, password: str
    ) -> None:
        """Send a confirmation link to the proposed new address.

        Note:
            Requires the current password as re-auth. OAuth-only accounts hold
            the unusable-password sentinel and therefore cannot use this flow as
            written - give them a password first (a "set password" flow) or wire
            a provider re-auth path before exposing email change to them.

        Note:
            Availability is checked best-effort and idempotently: if the address
            is already taken the token is silently skipped, so the response can't
            be used to probe which emails exist.
        """
        if not verify_password(password, self.repo.get(user, "hashed_password", "")):
            raise BadRequestException("Incorrect password")
        new_email_c = canonical_email(new_email)
        if new_email_c == canonical_email(self.repo.get(user, "email")):
            raise BadRequestException("New email matches current email")
        if not await self._email_within_limit(CHANGE_ACTION, new_email_c):
            return
        if await self.repo.get_by_email(db, new_email_c) is None:
            token = create_signed_token(
                self.secret_key,
                self.repo.user_id(user),
                CHANGE,
                expires_hours=self.change_ttl_hours,
                algorithm=self.algorithm,
                extra_claims={"new_email": new_email_c},
            )
            await self._deliver(
                DeliveryIntent(
                    kind="change_email",
                    token=token,
                    user=self.repo.to_dict(user),
                    recipient=new_email_c,
                    expires_in=self.change_ttl_hours * SECONDS_PER_HOUR,
                ),
                db,
            )

    async def confirm_email_change(self, db: AsyncSession, token: str) -> Any:
        """Apply a confirmed email change.

        Note:
            The confirmation link is delivered to, and clicked from, the new
            address, so completing this flow proves control of it - the new email
            is therefore marked verified (``email_verified=True``) alongside the
            address update.

        Note:
            Availability is re-checked before consuming the token so a token
            isn't burned when the address was taken in the meantime - but that
            check is best-effort: the DB unique constraint is the real backstop.
            A concurrent confirm to the same address surfaces as ``IntegrityError``,
            which is caught and surfaced as a clean duplicate error.
        """
        payload = verify_signed_token_full(token, self.secret_key, CHANGE, algorithm=self.algorithm)
        if payload is None:
            raise BadRequestException("Invalid or expired token")
        new_email = canonical_email(payload.get("new_email"))
        if not new_email:
            raise BadRequestException("Invalid token")
        if await self.repo.get_by_email(db, new_email) is not None:
            raise DuplicateValueException("Email already in use")
        user = await self.repo.get_by_id(db, payload["sub"])
        if user is None:
            raise BadRequestException("Invalid or expired token")
        if not await self._consume(token, self.change_ttl_hours * SECONDS_PER_HOUR):
            raise BadRequestException("Token already used")
        try:
            await self.repo.update(db, user, {"email": new_email, "email_verified": True})
        except IntegrityError as exc:
            await db.rollback()
            raise DuplicateValueException("Email already in use") from exc
        await self.hooks.run_after_email_changed(
            self.repo.to_dict(user), db=db, context=HookContext()
        )
        return user
