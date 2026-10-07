"""TOTP second factor: login challenges, enrollment, recovery codes."""

from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import logging
import secrets
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from ..exceptions import (
    BadRequestException,
    ForbiddenException,
    RateLimitException,
    UnauthorizedException,
)
from ..hooks import HookContext
from ..utils import get_client_ip, is_cross_site
from .cipher import SecretCipher
from .config import MfaConfig
from .constants import CHALLENGE_TOKEN_BYTES
from .recovery import generate_recovery_codes, hash_recovery_code, hash_recovery_codes, load_hashes
from .schemas import MfaChallenge
from .totp import generate_secret, matching_step, normalize_code, provisioning_uri

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import Request, Response
    from sqlalchemy.ext.asyncio import AsyncSession

    from ..core import AuthRuntime, Transport
    from ..storage.base import AbstractSessionStorage

__all__ = ["MfaService"]

logger = logging.getLogger("crudauth")

INVALID_CHALLENGE = "Invalid or expired MFA challenge"
RECOVERY_CODE_CLAIM_ATTEMPTS = 3


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _challenge_key(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class MfaService:
    """TOTP enrollment and verification, reachable as ``auth.mfa``.

    ``/login`` and ``/token`` call [challenge_login][crudauth.mfa.service.MfaService.challenge_login]
    after a correct password; ``/mfa/verify`` calls
    [complete_challenge][crudauth.mfa.service.MfaService.complete_challenge]. A
    hand-written login does the same to keep the second factor.

    Example:
        ```python
        user = await auth.authenticate_password(
            db, form.username, form.password, request=request, record_success=False
        )
        challenge = await auth.mfa.challenge_login(
            db, user, request=request, transport="session",
            lockout_identifier=form.username, options={},
        )
        if challenge is not None:
            return challenge
        ```
    """

    def __init__(
        self,
        *,
        runtime: AuthRuntime,
        config: MfaConfig,
        challenge_store: AbstractSessionStorage[MfaChallenge],
    ):
        self.runtime = runtime
        self.repo = runtime.repo
        self.hooks = runtime.hooks
        self.config = config
        self.challenges = challenge_store
        self._cipher = SecretCipher(config.encryption_keys)

    # --- state ---------------------------------------------------------------
    def is_enrolled(self, user: Any) -> bool:
        """Whether the account has a confirmed authenticator."""
        return self.repo.get(user, "totp_confirmed_at") is not None and bool(
            self.repo.get(user, "totp_secret_encrypted")
        )

    async def is_required(self, user: Any) -> bool:
        """Whether ``MfaConfig.required`` applies to this account."""
        required = self.config.required
        if isinstance(required, bool):
            return required
        result = required(user)
        if inspect.isawaitable(result):
            result = await result
        return bool(result)

    def recovery_codes_remaining(self, user: Any) -> int:
        return len(load_hashes(self.repo.get(user, "mfa_recovery_codes")))

    async def status(self, user: Any) -> dict[str, Any]:
        """``{"enabled", "required", "recovery_codes_remaining"}`` for ``GET /mfa``."""
        return {
            "enabled": self.is_enrolled(user),
            "required": await self.is_required(user),
            "recovery_codes_remaining": self.recovery_codes_remaining(user),
        }

    def _secret(self, user: Any) -> str | None:
        """The confirmed authenticator's secret, or ``None`` if it can't be decrypted."""
        token = self.repo.get(user, "totp_secret_encrypted")
        if not token:
            return None
        secret = self._cipher.decrypt(token)
        if secret is None:
            logger.error(
                "crudauth: the TOTP secret for user_id=%s can't be decrypted with "
                "MfaConfig.encryption_key",
                self.repo.user_id(user),
            )
        return secret

    def _setup_payload(self, user: Any, secret: str) -> dict[str, str]:
        account = (
            self.repo.get(user, "email")
            or self.repo.get(user, "username")
            or str(self.repo.user_id(user))
        )
        return {
            "secret": secret,
            "otpauth_uri": provisioning_uri(secret, issuer=self.config.issuer, account=account),
        }

    # --- codes ---------------------------------------------------------------
    async def _accept_totp(self, db: AsyncSession, user: Any, secret: str, code: str) -> bool:
        step = matching_step(secret, code)
        return step is not None and await self.repo.claim_totp_step(db, user, step)

    async def verify_totp(self, db: AsyncSession, user: Any, code: str) -> bool:
        """Check a code from the enrolled authenticator, claiming its time step.

        A step is accepted once, so the same code (or an older one) fails afterwards.
        """
        if not self.is_enrolled(user):
            return False
        secret = self._secret(user)
        return secret is not None and await self._accept_totp(db, user, secret, code)

    async def verify_code(
        self, db: AsyncSession, user: Any, code: str, *, context: HookContext | None = None
    ) -> bool:
        """Check an authenticator code, or else consume a recovery code.

        Fires ``on_after_recovery_code_used`` when a recovery code is spent.
        """
        if normalize_code(code) is not None:
            return await self.verify_totp(db, user, code)
        return await self._consume_recovery_code(db, user, code, context or HookContext())

    async def _consume_recovery_code(
        self, db: AsyncSession, user: Any, code: str, context: HookContext
    ) -> bool:
        if not self.is_enrolled(user):
            return False
        target = hash_recovery_code(code)
        for _ in range(RECOVERY_CODE_CLAIM_ATTEMPTS):
            stored = self.repo.get(user, "mfa_recovery_codes")
            hashes = load_hashes(stored)
            if not any(hmac.compare_digest(value, target) for value in hashes):
                return False
            remaining = json.dumps([value for value in hashes if value != target])
            if await self.repo.update_if_unchanged(
                db,
                user,
                {"mfa_recovery_codes": remaining},
                field="mfa_recovery_codes",
                expected=stored,
            ):
                await self.hooks.run_after_recovery_code_used(
                    self.repo.to_dict(user), db=db, context=context
                )
                await self.repo.refresh_if_expired(db, user)
                return True
        return False

    # --- enrollment ----------------------------------------------------------
    async def begin_setup(self, db: AsyncSession, user: Any) -> dict[str, str]:
        """Start (or restart) enrollment with a new secret.

        Returns:
            ``{"secret", "otpauth_uri"}`` for the authenticator app.

        Raises:
            BadRequestException: If an authenticator is already enabled.
        """
        if self.is_enrolled(user):
            raise BadRequestException("Two-factor authentication is already enabled.")
        secret = generate_secret()
        await self._store_pending(db, user, secret)
        return self._setup_payload(user, secret)

    async def _store_pending(self, db: AsyncSession, user: Any, secret: str) -> None:
        bound = f"{self.repo.token_version(user)}:{secret}"
        await self.repo.update(
            db,
            user,
            {
                "totp_secret_encrypted": self._cipher.encrypt(bound),
                "totp_confirmed_at": None,
                "totp_last_step": None,
                "mfa_recovery_codes": None,
            },
        )

    def _pending_secret(self, user: Any) -> str | None:
        """The secret of an unconfirmed setup, if the credentials haven't changed since.

        A pending secret is stored with the ``token_version`` it was issued under, so
        a password reset or change discards it: whoever saw it before can't have it
        confirmed by the owner afterwards.
        """
        token = self.repo.get(user, "totp_secret_encrypted")
        if self.repo.get(user, "totp_confirmed_at") is not None or not token:
            return None
        version, _, secret = (self._cipher.decrypt(token) or "").partition(":")
        if not secret or version != str(self.repo.token_version(user)):
            return None
        return secret

    async def _pending_or_new_secret(self, db: AsyncSession, user: Any) -> str:
        secret = self._pending_secret(user)
        if secret is None:
            secret = generate_secret()
            await self._store_pending(db, user, secret)
        return secret

    async def confirm_setup(
        self, db: AsyncSession, user: Any, code: str, *, context: HookContext | None = None
    ) -> list[str]:
        """Enable the pending authenticator once a code from it checks out.

        Returns:
            The recovery codes, in plain text, for the user to store. They aren't
            retrievable later.

        Raises:
            BadRequestException: If MFA is already enabled or no setup is pending.
            UnauthorizedException: If the code is wrong.
        """
        if self.is_enrolled(user):
            raise BadRequestException("Two-factor authentication is already enabled.")
        secret = self._pending_secret(user)
        if secret is None:
            raise BadRequestException("No authenticator setup is pending.")
        if not await self._accept_totp(db, user, secret, code):
            raise UnauthorizedException("Invalid code")
        codes = await self._enable(db, user, secret, context or HookContext())
        if codes is None:
            raise BadRequestException("Two-factor authentication is already enabled.")
        return codes

    async def _enable(
        self, db: AsyncSession, user: Any, secret: str, context: HookContext
    ) -> list[str] | None:
        """Confirm the pending authenticator and issue recovery codes.

        Returns ``None`` when a concurrent request confirmed it first, so only one
        set of recovery codes is ever handed out.
        """
        codes = generate_recovery_codes(self.config.recovery_code_count)
        enabled = await self.repo.update_if_unchanged(
            db,
            user,
            {
                "totp_secret_encrypted": self._cipher.encrypt(secret),
                "totp_confirmed_at": _utcnow(),
                "mfa_recovery_codes": hash_recovery_codes(codes),
            },
            field="totp_confirmed_at",
            expected=None,
        )
        if not enabled:
            return None
        await self.hooks.run_after_mfa_enabled(self.repo.to_dict(user), db=db, context=context)
        return codes

    async def disable(
        self, db: AsyncSession, user: Any, *, context: HookContext | None = None
    ) -> None:
        """Remove the authenticator and recovery codes (an admin reset calls this directly)."""
        await self.repo.update(
            db,
            user,
            {
                "totp_secret_encrypted": None,
                "totp_confirmed_at": None,
                "totp_last_step": None,
                "mfa_recovery_codes": None,
            },
        )
        await self.hooks.run_after_mfa_disabled(
            self.repo.to_dict(user), db=db, context=context or HookContext()
        )

    async def regenerate_recovery_codes(self, db: AsyncSession, user: Any) -> list[str]:
        """Replace every recovery code with a new set.

        Raises:
            BadRequestException: If MFA isn't enabled.
        """
        if not self.is_enrolled(user):
            raise BadRequestException("Two-factor authentication isn't enabled.")
        codes = generate_recovery_codes(self.config.recovery_code_count)
        await self.repo.update(db, user, {"mfa_recovery_codes": hash_recovery_codes(codes)})
        return codes

    # --- login ---------------------------------------------------------------
    async def challenge_login(
        self,
        db: AsyncSession,
        user: Any,
        *,
        request: Request,
        transport: str,
        lockout_identifier: str,
        options: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Start the second step of a login whose password checked out.

        Args:
            db: Active async session.
            user: The authenticated user row.
            request: The login request.
            transport: Name of the transport that finishes the login.
            lockout_identifier: The login identifier the lockout is keyed on; a
                correct code clears it, a wrong one counts against it.
            options: What the transport's ``complete_login`` needs afterwards.

        Returns:
            ``None`` when the account neither uses nor requires MFA (the lockout is
            cleared, and the caller completes the login). Otherwise
            ``{"mfa_required": True, "challenge", "expires_in"}``, plus
            ``setup: {"secret", "otpauth_uri"}`` when a required account enrolls now.
        """
        ip_address = get_client_ip(request, self.runtime.trusted_proxy_hops)
        enrolled = self.is_enrolled(user)
        if not enrolled and not await self.is_required(user):
            await self.runtime.record_login_success(ip_address, lockout_identifier)
            return None
        setup_secret = None if enrolled else await self._pending_or_new_secret(db, user)
        token = secrets.token_urlsafe(CHALLENGE_TOKEN_BYTES)
        ttl = self.config.challenge_ttl_seconds
        await self.challenges.create(
            MfaChallenge(
                account_id=self.repo.user_id(user),
                token_version=self.repo.token_version(user),
                transport=transport,
                setup=setup_secret is not None,
                lockout_identifier=lockout_identifier,
                ip_address=ip_address,
                options=options,
            ),
            session_id=_challenge_key(token),
            expiration=ttl,
        )
        body: dict[str, Any] = {"mfa_required": True, "challenge": token, "expires_in": ttl}
        if setup_secret is not None:
            body["setup"] = self._setup_payload(user, setup_secret)
        return body

    async def describe_challenge(self, db: AsyncSession, token: str) -> dict[str, Any]:
        """``{"setup": {"secret", "otpauth_uri"} | None}`` for a live challenge.

        For a frontend that received only the challenge token (an OAuth redirect)
        and needs the enrollment details. Doesn't count as an attempt.

        Raises:
            BadRequestException: If the challenge doesn't exist.
        """
        challenge = await self.challenges.get(_challenge_key(token), MfaChallenge)
        user = None if challenge is None else await self.repo.get_by_id(db, challenge.account_id)
        if challenge is None or user is None or not self.repo.is_active(user):
            raise BadRequestException(INVALID_CHALLENGE)
        secret = self._pending_secret(user) if challenge.setup else None
        return {"setup": None if secret is None else self._setup_payload(user, secret)}

    async def complete_challenge(
        self,
        db: AsyncSession,
        token: str,
        code: str,
        *,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        """Check the code for a challenge and issue the credential its login started.

        An authenticator code or a recovery code answers a login challenge; a setup
        challenge needs a code from the authenticator being enrolled, and the
        response then carries its ``recovery_codes``. Each call counts toward the
        challenge's ``max_code_attempts`` and the login lockout; a correct code
        consumes the challenge and clears the lockout.

        Returns:
            The transport's login response, plus ``recovery_codes`` after
            enrollment and ``redirect_to`` for an OAuth login.

        Raises:
            BadRequestException: Unknown, expired, used-up or exhausted challenge, or
                the password was reset or changed since the challenge began.
            ForbiddenException: A cross-site request for a cookie-setting login.
            RateLimitException: The login lockout is engaged.
            UnauthorizedException: Wrong code.
        """
        key = _challenge_key(token)
        pending = await self.challenges.get(key, MfaChallenge)
        if pending is None:
            raise BadRequestException(INVALID_CHALLENGE)
        transport = self._transport(pending.transport)
        if transport.sets_cookies and is_cross_site(request):
            raise ForbiddenException("Cross-site login requests are not allowed.")

        def count_attempt(challenge: MfaChallenge) -> None:
            challenge.attempts += 1

        challenge = await self.challenges.modify(
            key, MfaChallenge, count_attempt, reset_expiration=False
        )
        if challenge is None:
            raise BadRequestException(INVALID_CHALLENGE)
        if challenge.attempts > self.config.max_code_attempts:
            await self.challenges.delete(key)
            raise BadRequestException(INVALID_CHALLENGE)
        lockout = self.runtime.lockout
        if lockout is not None:
            allowed, _, retry_after = await lockout.check_and_record(
                challenge.ip_address, challenge.lockout_identifier, success=False
            )
            if not allowed:
                await self.challenges.delete(key)
                raise RateLimitException(
                    "Too many login attempts. Try again later.", retry_after=retry_after
                )
        user = await self.repo.get_by_id(db, challenge.account_id)
        if (
            user is None
            or not self.repo.is_active(user)
            or self.repo.token_version(user) != challenge.token_version
        ):
            await self.challenges.delete(key)
            raise BadRequestException(INVALID_CHALLENGE)

        context = HookContext(
            ip_address=get_client_ip(request, self.runtime.trusted_proxy_hops),
            user_agent=request.headers.get("user-agent"),
            transport=challenge.transport,
            request=request,
        )
        secret = None
        if challenge.setup:
            secret = None if self.is_enrolled(user) else self._pending_secret(user)
            accepted = secret is not None and await self._accept_totp(db, user, secret, code)
        else:
            accepted = await self.verify_code(db, user, code, context=context)
        if not accepted:
            if challenge.attempts >= self.config.max_code_attempts:
                await self.challenges.delete(key)
            raise UnauthorizedException("Invalid code")
        if await self.challenges.get_and_delete(key, MfaChallenge) is None:
            raise BadRequestException(INVALID_CHALLENGE)

        recovery_codes = (
            await self._enable(db, user, secret, context) if secret is not None else None
        )
        await self.runtime.record_login_success(challenge.ip_address, challenge.lockout_identifier)
        body = await transport.complete_login(request, response, user, challenge.options)
        if recovery_codes is not None:
            body["recovery_codes"] = recovery_codes
        if "redirect_to" in challenge.options:
            body["redirect_to"] = challenge.options["redirect_to"]
        return body

    def _transport(self, name: str) -> Transport:
        for transport in self.runtime.transports:
            if transport.name == name:
                return transport
        raise BadRequestException(INVALID_CHALLENGE)
