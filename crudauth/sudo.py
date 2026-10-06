"""Sudo mode - short-lived re-authentication for sensitive actions.

A logged-in session proves *who* you are; sudo proves *you're still at the
keyboard right now*. Gate destructive/admin actions (delete account, rotate
keys, change billing) behind a recent password re-entry instead of trusting a
long-lived session that may have been left open or hijacked.

Elevation is stamped on the **session** (an absolute expiry in session
metadata), so it dies with the session - logout or revocation clears it for
free - and it requires a session transport (bearer/api-key credentials have no
server-side session to stamp). Repeated wrong passwords trip a dedicated
``sudo:*`` lockout, separate from the login lockout so one can't mask the other.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from .exceptions import ForbiddenException, SudoLockoutError, UnauthorizedException
from .hooks import HookContext
from .ratelimit.constants import SUDO_NAMESPACE
from .transports.session.constants import SUDO_ELEVATED_UNTIL_META_KEY
from .transports.session.schemas import SessionData
from .transports.session.transport import SessionTransport
from .utils import verify_password_async

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import Request
    from sqlalchemy.ext.asyncio import AsyncSession

    from .hooks import AuthHooks
    from .mfa.service import MfaService
    from .principal import Principal
    from .ratelimit.base import RateLimiterBackend
    from .repository import UserRepository
    from .transports.session.manager import SessionManager

__all__ = ["SudoConfig", "SudoManager"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class SudoConfig:
    """Tuning for sudo elevation and its lockout.

    Args:
        window_seconds: How long an elevation stays valid after a correct
            password (the "you're still here" window).
        max_attempts: Wrong-password attempts allowed before the sudo lockout
            trips.
        lockout_seconds: How long sudo stays locked once tripped. The login flow
            is unaffected - only further elevation is blocked.
    """

    window_seconds: int = 300
    max_attempts: int = 3
    lockout_seconds: int = 900


class SudoManager:
    """Elevate and check sudo state for session-backed principals.

    Built by [CRUDAuth][crudauth.crud_auth.CRUDAuth] when ``sudo=`` is set and a
    session transport is configured, and exposed as ``auth.sudo``.

    Example:
        ```python
        @app.post("/sudo")
        async def sudo(body: SudoIn, request: Request, user=Depends(auth.current_user())):
            await auth.sudo.elevate(user, body.password, request=request)
        ```
    """

    def __init__(
        self,
        *,
        session_manager: SessionManager,
        repo: UserRepository,
        backend: RateLimiterBackend | None,
        hooks: AuthHooks,
        config: SudoConfig,
        mfa: MfaService | None = None,
    ):
        self.session_manager = session_manager
        self.repo = repo
        self.backend = backend
        self.hooks = hooks
        self.config = config
        self.mfa = mfa

    def _session_id(self, principal: Principal) -> str:
        """The principal's session id, or raise 403 for a non-session credential."""
        session_id = principal.metadata.get("session_id")
        if principal.transport != SessionTransport.name or not session_id:
            raise ForbiddenException("Sudo requires a session-backed login.")
        return str(session_id)

    async def elevate(
        self,
        principal: Principal,
        password: str | None = None,
        *,
        code: str | None = None,
        db: AsyncSession | None = None,
        request: Request | None = None,
    ) -> datetime:
        """Re-verify ``password``, or an authenticator ``code``, and stamp the session as elevated.

        A ``code`` needs MFA configured, an enrolled account, and the request's ``db``
        (the code's time step is claimed so it can't be reused).

        Returns the absolute instant the elevation expires.

        Raises:
            ValueError: Neither or both of ``password`` and ``code``, or a ``code``
                without MFA or ``db``.
            ForbiddenException: The principal isn't session-backed, or its
                session has since vanished (stale credential).
            UnauthorizedException: Wrong password or code (counts toward the lockout).
            SudoLockoutError: Too many wrong attempts; sudo is locked (429 +
                ``Retry-After``). The elevation stamp is cleared on lockout.
        """
        if (password is None) == (code is None):
            raise ValueError("Pass exactly one of password or code.")
        if code is not None and (self.mfa is None or db is None):
            raise ValueError("Elevating with a code needs mfa=MfaConfig(...) and the request's db.")
        session_id = self._session_id(principal)
        user = principal.user
        if user is None:
            raise ForbiddenException("Sudo requires a session-backed login.")
        user_id = self.repo.user_id(user)

        await self._guard_locked(user_id)
        attempt = await self._count_attempt(user_id)
        if attempt > self.config.max_attempts:
            await self._lock(session_id, user_id)

        if not await self._verify(user, password, code, db):
            if attempt >= self.config.max_attempts:
                await self._lock(session_id, user_id)
            raise UnauthorizedException("Incorrect password" if code is None else "Invalid code")

        await self._clear_failures(user_id)
        elevated_until = _utcnow() + timedelta(seconds=self.config.window_seconds)

        def stamp(session: SessionData) -> None:
            session.metadata[SUDO_ELEVATED_UNTIL_META_KEY] = elevated_until.isoformat()

        stamped = await self.session_manager.modify_session(session_id, stamp)
        if stamped is None:
            raise ForbiddenException("Session no longer exists.")

        await self.hooks.run_after_sudo(
            self.repo.to_dict(user),
            request=request,
            context=HookContext(transport=SessionTransport.name, request=request),
        )
        return elevated_until

    async def _verify(
        self, user: Any, password: str | None, code: str | None, db: AsyncSession | None
    ) -> bool:
        if code is not None and self.mfa is not None and db is not None:
            return await self.mfa.verify_totp(db, user, code)
        return password is not None and await verify_password_async(
            password, self.repo.get(user, "hashed_password")
        )

    async def is_elevated(self, principal: Principal) -> bool:
        """Whether the principal's session holds an unexpired sudo elevation."""
        session_id = principal.metadata.get("session_id")
        if principal.transport != SessionTransport.name or not session_id:
            return False
        session = await self.session_manager.get_session(str(session_id))
        if session is None:
            return False
        stamp = session.metadata.get(SUDO_ELEVATED_UNTIL_META_KEY)
        if not stamp:
            return False
        try:
            expires_at = datetime.fromisoformat(stamp)
        except (ValueError, TypeError):
            return False
        return _utcnow() < expires_at

    # --- lockout (its own namespace on the shared limiter) -------------------
    def _fail_key(self, user_id: Any) -> str:
        return f"{SUDO_NAMESPACE}:fail:{user_id}"

    def _lock_key(self, user_id: Any) -> str:
        return f"{SUDO_NAMESPACE}:lock:{user_id}"

    async def _guard_locked(self, user_id: Any) -> None:
        if self.backend is None:
            return
        ttl = await self.backend.get_ttl(self._lock_key(user_id))
        if ttl > 0:
            raise SudoLockoutError("Too many attempts. Try again later.", retry_after=ttl)

    async def _count_attempt(self, user_id: Any) -> int:
        """Count an attempt before checking the password, so concurrent guesses share the cap."""
        if self.backend is None:
            return 0
        return await self.backend.increment(self._fail_key(user_id), 1, self.config.window_seconds)

    async def _lock(self, session_id: str, user_id: Any) -> None:
        """Lock sudo, drop the elevation, and raise."""
        assert self.backend is not None
        await self.backend.increment(self._lock_key(user_id), 1, self.config.lockout_seconds)
        await self.backend.delete(self._fail_key(user_id))
        await self._clear_elevation(session_id)
        raise SudoLockoutError(
            "Too many attempts. Try again later.", retry_after=self.config.lockout_seconds
        )

    async def _clear_failures(self, user_id: Any) -> None:
        if self.backend is not None:
            await self.backend.delete(self._fail_key(user_id))

    async def _clear_elevation(self, session_id: str) -> None:
        def unstamp(session: SessionData) -> None:
            session.metadata.pop(SUDO_ELEVATED_UNTIL_META_KEY, None)

        await self.session_manager.modify_session(session_id, unstamp)
