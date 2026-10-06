"""Orchestrates verify / reset / change-email flows on top of signed tokens."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import TYPE_CHECKING, Any, NamedTuple

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
from ..exceptions import BadRequestException, DuplicateValueException, ValueTooLongException
from ..hooks import AuthHooks, HookContext
from ..ratelimit import RateLimit
from ..repository import UserRepository
from ..password import PasswordContext, PasswordPolicy
from ..storage.base import AbstractSessionStorage
from ..transports.bearer.tokens import create_signed_token, verify_signed_token_full
from ..utils import (
    canonical_email,
    get_password_hash_async,
    safe_redirect_path,
    verify_password_async,
)
from .channel import DeliveryChannel, DeliveryIntent, EmailChannel
from .config import EmailConfig
from .constants import (
    CHANGE,
    CHANGE_ACTION,
    EXISTING_ACCOUNT_ACTION,
    REDIRECT_CLAIM,
    RESET,
    RESET_ACTION,
    STATE_CLAIM,
    STATE_DIGEST_CHARS,
    VERIFY,
    VERIFY_ACTION,
)

if TYPE_CHECKING:  # pragma: no cover
    from ..ratelimit import RateLimiterBackend
    from ..transports.session.manager import SessionManager

__all__ = ["EmailFlowService", "EmailFlowResult"]

logger = logging.getLogger("crudauth")


class _UsedToken(BaseModel):
    used: bool = True


class EmailFlowResult(NamedTuple):
    """What a confirmed recovery flow produced.

    Attributes:
        user: The affected user row.
        redirect_to: Where the app should send the person next - the
            ``redirect_to`` they asked for when the link was requested, if it
            survived validation, else ``None``.
    """

    user: Any
    redirect_to: str | None


class EmailFlowService:
    """Mints/verifies signed tokens and drives the recovery flows.

    The package owns token lifecycle; *delivery* is pluggable via one or more
    [DeliveryChannel][crudauth.email.channel.DeliveryChannel]s (email is the
    built-in one). Trigger endpoints are throttled two ways: a per-IP edge limit
    (in the router) and a **silent** per-target-email limit here - silent because
    a 429 on a victim's address would re-introduce the enumeration oracle and
    hand an attacker a DoS lever against that user.

    Each token carries a fingerprint of the account state it authorizes (an
    HMAC over, never a copy of, that state), so it stops working once that state
    moves on: a reset token after the password or recovery value changes, an
    email-change token after the password, email, or ``token_version`` changes,
    and a verification token after the recovery value changes.

    Construction is additive: pass ``config=EmailConfig(...)`` (back-compat, which
    builds an [EmailChannel][crudauth.email.channel.EmailChannel] and seeds the
    token TTLs) and/or ``channels=[...]`` plus explicit ``*_ttl_hours``. Reachable
    as ``auth.emails`` (``None`` when no recovery is configured).

    Example:
        ```python
        if auth.emails is not None:
            await auth.emails.request_password_reset(db, email)
        ```
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
        password_policy: PasswordPolicy | None = None,
    ):
        self.repo = repo
        self.password_policy = password_policy or PasswordPolicy()
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
        self._email_channels = [channel for channel in channel_list if channel.sends_email]

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

    @property
    def supports_email_change(self) -> bool:
        """Whether change-email can run: the model has an ``email`` column and at
        least one channel emails the recipient (``sends_email``)."""
        return self.repo.has("email") and bool(self._email_channels)

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

        A ``change_email`` intent goes only to the channels that email the
        recipient: its token proves control of the new address, so it must not
        reach a phone or any other destination a channel loads for itself.
        """
        channels = self._email_channels if intent.kind == "change_email" else self._channels
        for channel in channels:
            try:
                await channel.deliver(intent, db)
            except Exception:
                logger.warning(
                    "crudauth: %s delivery via %s failed",
                    intent.kind,
                    type(channel).__name__,
                    exc_info=True,
                )

    # --- account-state binding -----------------------------------------------
    def _state_fingerprint(self, purpose: str, user: Any) -> str:
        """HMAC, keyed by the app secret, over the account state a token of ``purpose`` authorizes."""
        repo = self.repo
        password_hash = repo.get(user, "hashed_password")
        recovery_value = repo.get(user, repo.recovery) if repo.recovery is not None else None
        state = {
            VERIFY: [recovery_value],
            RESET: [password_hash, recovery_value],
            CHANGE: [password_hash, repo.get(user, "email"), repo.token_version(user)],
        }[purpose]
        message = json.dumps([purpose, *state], default=str).encode()
        digest = hmac.new(self.secret_key.encode(), message, hashlib.sha256).hexdigest()
        return digest[:STATE_DIGEST_CHARS]

    @staticmethod
    def _redirect_claim(redirect_to: str | None) -> dict[str, str]:
        """The ``redirect_to`` claim for a token, or nothing when it can't be honored.

        A destination that isn't a same-origin relative path is dropped rather
        than raised on: someone verifying their email must not be stopped because
        the app asked to send them somewhere unsafe afterwards.
        """
        target = safe_redirect_path(redirect_to, default="") if redirect_to else ""
        return {REDIRECT_CLAIM: target} if target else {}

    @staticmethod
    def _redirect_from(payload: dict[str, Any]) -> str | None:
        """The destination a token carries, re-validated at redemption."""
        claim = payload.get(REDIRECT_CLAIM)
        target = safe_redirect_path(claim, default="") if isinstance(claim, str) else ""
        return target or None

    def _mint_token(self, purpose: str, user: Any, expires_hours: int, **claims: Any) -> str:
        """Sign a ``purpose`` token for ``user``, bound to the account's current state."""
        return create_signed_token(
            self.secret_key,
            self.repo.user_id(user),
            purpose,
            expires_hours=expires_hours,
            algorithm=self.algorithm,
            extra_claims={**claims, STATE_CLAIM: self._state_fingerprint(purpose, user)},
        )

    async def _redeem_token(
        self, db: AsyncSession, token: str, purpose: str
    ) -> tuple[Any, dict[str, Any]]:
        """Return the user and claims of a valid ``purpose`` token.

        Raises:
            BadRequestException: If the token is invalid or expired, its user is
                gone or inactive, or the account has left the state the token was
                minted for.
        """
        payload = verify_signed_token_full(
            token, self.secret_key, purpose, algorithm=self.algorithm
        )
        if payload is None:
            raise BadRequestException("Invalid or expired token")
        user = await self.repo.get_by_id(db, payload["sub"])
        if (
            user is None
            or not self.repo.is_active(user)
            or not hmac.compare_digest(
                str(payload.get(STATE_CLAIM, "")), self._state_fingerprint(purpose, user)
            )
        ):
            raise BadRequestException("Invalid or expired token")
        return user, payload

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

    async def notify_existing_account(self, value: str) -> None:
        """Tell an existing owner someone tried to register with their email or
        recovery value (``value``, which is also the notice's recipient).

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
        if not await self._email_within_limit(EXISTING_ACCOUNT_ACTION, value):
            return
        await self._deliver(
            DeliveryIntent(
                kind="existing_account", token=None, user={}, recipient=value, expires_in=0
            ),
            None,
        )

    # --- recovery-factor verification ----------------------------------------
    async def request_recovery_verification(
        self, db: AsyncSession, value: str, *, redirect_to: str | None = None
    ) -> None:
        """Send a verification token for the contract's recovery factor.

        Idempotent; never reveals account existence. An inactive account is sent
        nothing, exactly as if it didn't exist. The user is looked up by the
        recovery factor (email for email recovery, phone for phone recovery) and
        the token is delivered to that factor's value over the configured channel.

        Args:
            db: Active async session.
            value: The recovery value to look up and deliver to.
            redirect_to: Where the app should send the person once they confirm.
                It rides inside the signed token, so the emailed link is unchanged
                and the destination survives the link being opened on another
                device. Only a same-origin relative path is carried; anything else
                is dropped and the flow proceeds without one.
        """
        factor = self.repo.recovery
        if factor is None:
            return
        if not await self._email_within_limit(VERIFY_ACTION, value):
            return
        user = await self.repo.get_by_field(db, factor, value)
        if user is None or not self.repo.is_active(user) or self.repo.recovery_verified(user):
            return
        token = self._mint_token(
            VERIFY, user, self.verify_ttl_hours, **self._redirect_claim(redirect_to)
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

    async def confirm_recovery_verification(self, db: AsyncSession, token: str) -> EmailFlowResult:
        """Verify the signed token and mark the user's email verified (one-time-use).

        Args:
            db: Active async session.
            token: The signed verification token from the emailed link.

        Returns:
            The verified user row and the ``redirect_to`` the request carried, as
            an [EmailFlowResult][crudauth.email.service.EmailFlowResult].

        Raises:
            BadRequestException: If the token is invalid, expired, or already used,
                or the recovery value changed since it was sent.
        """
        user, payload = await self._redeem_token(db, token, VERIFY)
        if not await self._consume(token, self.verify_ttl_hours * SECONDS_PER_HOUR):
            raise BadRequestException("Token already used")
        if not self.repo.recovery_verified(user):
            await self.repo.mark_recovery_verified(db, user)
            await self.hooks.run_after_recovery_verified(
                self.repo.to_dict(user), db=db, context=HookContext()
            )
        return EmailFlowResult(user, self._redirect_from(payload))

    # --- password reset ------------------------------------------------------
    async def request_password_reset(
        self, db: AsyncSession, value: str, *, redirect_to: str | None = None
    ) -> None:
        """Send a reset token over the configured channel. Idempotent; never reveals
        account existence. Looked up by, and delivered to, the recovery factor. An
        inactive account is sent nothing, exactly as if it didn't exist.

        Args:
            db: Active async session.
            value: The recovery value to look up and deliver to.
            redirect_to: Where the app should send the person once the password is
                reset; carried inside the signed token, same-origin paths only.
        """
        factor = self.repo.recovery
        if factor is None:
            return
        if not await self._email_within_limit(RESET_ACTION, value):
            return
        user = await self.repo.get_by_field(db, factor, value)
        if user is None or not self.repo.is_active(user):
            return
        token = self._mint_token(
            RESET, user, self.reset_ttl_hours, **self._redirect_claim(redirect_to)
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

    async def reset_password(
        self, db: AsyncSession, token: str, new_password: str
    ) -> EmailFlowResult:
        """Reset the password and evict every outstanding credential.

        Args:
            db: Active async session.
            token: The signed reset token from the emailed link.
            new_password: The new plaintext password (hashed before storage).

        Returns:
            The updated user row and the ``redirect_to`` the request carried, as
            an [EmailFlowResult][crudauth.email.service.EmailFlowResult].

        Raises:
            BadRequestException: If the token is invalid, expired, or already used,
                or the password or recovery value changed since it was sent.
            PasswordPolicyException: If ``new_password`` fails the password policy. The
                token isn't used up, so the user can retry with a stronger password.

        Note:
            A reset is attacker-eviction: it often follows a compromise, so any
            credential an attacker holds must die with it. Server-side sessions
            are terminated, and the user's ``token_version`` is bumped - which
            invalidates all outstanding bearer access and refresh tokens (their
            ``ver`` claim is now stale). Bearer eviction needs a ``token_version``
            column; without it (a custom model that omits it) only sessions are
            evicted.
        """
        user, payload = await self._redeem_token(db, token, RESET)
        await self.password_policy.enforce(
            new_password, PasswordContext.for_user(self.repo, "reset", user), field="new_password"
        )
        if not await self._consume(token, self.reset_ttl_hours * SECONDS_PER_HOUR):
            raise BadRequestException("Token already used")
        await self.repo.update(
            db, user, {"hashed_password": await get_password_hash_async(new_password)}
        )
        await self.repo.increment_token_version(db, user)
        if self.session_manager is not None:
            await self.session_manager.terminate_all_user_sessions(
                self.repo.user_id(user), reason="password_reset"
            )
        await self.hooks.run_after_password_reset(
            self.repo.to_dict(user), db=db, context=HookContext()
        )
        return EmailFlowResult(user, self._redirect_from(payload))

    # --- email change --------------------------------------------------------
    async def request_email_change(
        self,
        db: AsyncSession,
        user: Any,
        new_email: str,
        password: str,
        *,
        redirect_to: str | None = None,
    ) -> None:
        """Send a confirmation link to the proposed new address.

        Args:
            db: Active async session.
            user: The authenticated user changing their address.
            new_email: The proposed address.
            password: The current password, as re-auth.
            redirect_to: Where the app should send the person once the new address
                is confirmed; carried inside the signed token, same-origin paths only.

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
        if not await verify_password_async(password, self.repo.get(user, "hashed_password")):
            raise BadRequestException("Incorrect password")
        new_email_c = canonical_email(new_email)
        limit = self.repo.exceeds_length("email", new_email_c)
        if limit is not None:
            raise ValueTooLongException({"new_email": limit})
        if new_email_c == canonical_email(self.repo.get(user, "email")):
            raise BadRequestException("New email matches current email")
        if not await self._email_within_limit(CHANGE_ACTION, new_email_c):
            return
        if await self.repo.get_by_email(db, new_email_c) is None:
            token = self._mint_token(
                CHANGE,
                user,
                self.change_ttl_hours,
                new_email=new_email_c,
                **self._redirect_claim(redirect_to),
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

    async def confirm_email_change(self, db: AsyncSession, token: str) -> EmailFlowResult:
        """Apply a confirmed email change.

        Returns:
            The updated user row and the ``redirect_to`` the request carried, as
            an [EmailFlowResult][crudauth.email.service.EmailFlowResult].

        Note:
            The confirmation link is delivered to, and clicked from, the new
            address, so completing this flow proves control of it - the new email
            is therefore marked verified (``email_verified=True``) alongside the
            address update. The previous address, if any, gets an ``email_changed``
            notice, so an owner learns their address was replaced.

        Note:
            Availability is re-checked before consuming the token so a token
            isn't burned when the address was taken in the meantime - but that
            check is best-effort: the DB unique constraint is the real backstop.
            A concurrent confirm to the same address surfaces as ``IntegrityError``,
            which is caught and surfaced as a clean duplicate error.
        """
        user, payload = await self._redeem_token(db, token, CHANGE)
        new_email = canonical_email(payload.get("new_email"))
        if not new_email:
            raise BadRequestException("Invalid token")
        if await self.repo.get_by_email(db, new_email) is not None:
            raise DuplicateValueException("Email already in use")
        if not await self._consume(token, self.change_ttl_hours * SECONDS_PER_HOUR):
            raise BadRequestException("Token already used")
        old_email = self.repo.get(user, "email")
        try:
            await self.repo.update(db, user, {"email": new_email, "email_verified": True})
        except IntegrityError as exc:
            await db.rollback()
            raise DuplicateValueException("Email already in use") from exc
        if old_email:
            await self._deliver(
                DeliveryIntent(
                    kind="email_changed",
                    token=None,
                    user=self.repo.to_dict(user),
                    recipient=old_email,
                    expires_in=0,
                ),
                db,
            )
        await self.hooks.run_after_email_changed(
            self.repo.to_dict(user), db=db, context=HookContext()
        )
        return EmailFlowResult(user, self._redirect_from(payload))
