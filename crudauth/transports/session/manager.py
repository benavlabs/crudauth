"""``SessionManager`` - server-side sessions, CSRF, lockout, device management.

Decoupled from any global settings: every policy knob is a constructor argument.
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Request, Response

from ...constants import (
    CSRF_TOKEN_BYTES,
    DEFAULT_CLEANUP_INTERVAL_MINUTES,
    DEFAULT_MAX_SESSIONS_PER_USER,
    DEFAULT_REMEMBER_ME_DAYS,
    DEFAULT_SESSION_TIMEOUT_MINUTES,
)
from ...core import SameSite
from ...ratelimit import LockoutPolicy
from ...storage.base import AbstractSessionStorage
from ...utils import get_client_ip
from .constants import (
    CSRF_COOKIE_NAME,
    CSRF_TOKEN_ID_META_KEY,
    REMEMBER_ME_META_KEY,
    SESSION_COOKIE_NAME,
)
from .schemas import CSRFToken, SessionData
from .useragent import parse_user_agent

__all__ = ["SessionManager"]

logger = logging.getLogger("crudauth.session")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SessionManager:
    def __init__(
        self,
        session_storage: AbstractSessionStorage[SessionData],
        *,
        csrf_storage: AbstractSessionStorage[CSRFToken] | None = None,
        max_sessions_per_user: int = DEFAULT_MAX_SESSIONS_PER_USER,
        session_timeout_minutes: int = DEFAULT_SESSION_TIMEOUT_MINUTES,
        remember_me_days: int = DEFAULT_REMEMBER_ME_DAYS,
        cleanup_interval_minutes: int = DEFAULT_CLEANUP_INTERVAL_MINUTES,
        csrf_token_bytes: int = CSRF_TOKEN_BYTES,
        lockout: LockoutPolicy | None = None,
        cookie_secure: bool = True,
        cookie_samesite: SameSite = "lax",
        cookie_path: str = "/",
        session_cookie_name: str = SESSION_COOKIE_NAME,
        csrf_cookie_name: str = CSRF_COOKIE_NAME,
        trusted_proxy_hops: int = 0,
    ):
        self.storage = session_storage
        self.csrf_storage = csrf_storage
        self.max_sessions = max_sessions_per_user
        self.session_timeout = timedelta(minutes=session_timeout_minutes)
        self.remember_me_timeout = timedelta(days=remember_me_days)
        self.cleanup_interval = timedelta(minutes=cleanup_interval_minutes)
        self.last_cleanup = _utcnow()
        self.csrf_token_bytes = csrf_token_bytes
        self.lockout = lockout
        self.cookie_secure = cookie_secure
        self.cookie_samesite = cookie_samesite
        self.cookie_path = cookie_path
        self.session_cookie_name = session_cookie_name
        self.csrf_cookie_name = csrf_cookie_name
        self.trusted_proxy_hops = trusted_proxy_hops

    # --- timeout helpers -----------------------------------------------------
    def timeout_seconds_for(self, metadata: dict[str, Any] | None) -> int:
        if metadata and metadata.get(REMEMBER_ME_META_KEY):
            return int(self.remember_me_timeout.total_seconds())
        return int(self.session_timeout.total_seconds())

    def _is_idle_expired(self, session: SessionData, now: datetime) -> bool:
        window = timedelta(seconds=self.timeout_seconds_for(session.metadata))
        return session.last_activity < now - window

    # --- lifecycle -----------------------------------------------------------
    async def create_session(
        self,
        request: Request,
        user_id: Any,
        metadata: dict[str, Any] | None = None,
        expiration_seconds: int | None = None,
    ) -> tuple[str, str]:
        """Create a session + CSRF token. Returns ``(session_id, csrf_token)``.

        Note:
            The CSRF token id is stored on the session so its TTL can slide
            forward alongside the session in [validate_session][crudauth.transports.session.manager.SessionManager.validate_session].
        """
        user_agent = request.headers.get("user-agent", "")
        device_info = parse_user_agent(user_agent).model_dump()
        ip_address = get_client_ip(request, self.trusted_proxy_hops)

        await self._enforce_session_limit(user_id)

        session = SessionData(
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            device_info=device_info,
            metadata=metadata or {},
        )
        ttl = (
            expiration_seconds
            if expiration_seconds is not None
            else self.timeout_seconds_for(session.metadata)
        )
        session_id = session.session_id
        csrf_token = await self._generate_csrf_token(user_id, session_id, ttl)
        if csrf_token:
            session.metadata[CSRF_TOKEN_ID_META_KEY] = csrf_token
        await self.storage.create(session, session_id=session_id, expiration=ttl)
        return session_id, csrf_token

    async def validate_session(
        self, session_id: str, update_activity: bool = True
    ) -> SessionData | None:
        """Return the live session for ``session_id``, or ``None`` if invalid/idle-expired.

        Note:
            On activity, the CSRF token's TTL is slid forward together with the
            session's - otherwise it would expire out from under a session kept
            alive by activity and 403 later mutations.
        """
        if not session_id:
            return None
        session = await self.storage.get(session_id, SessionData)
        if session is None:
            return None
        now = _utcnow()
        if self._is_idle_expired(session, now):
            await self.terminate_session(
                session_id, reason="session_timeout", user_id=session.user_id
            )
            return None
        if update_activity:
            session.last_activity = now
            ttl = self.timeout_seconds_for(session.metadata)
            await self.storage.update(session_id, session, expiration=ttl)
            csrf_id = session.metadata.get(CSRF_TOKEN_ID_META_KEY)
            if csrf_id and self.csrf_storage is not None:
                await self.csrf_storage.extend(csrf_id, ttl)
        return session

    async def terminate_session(
        self, session_id: str, reason: str = "manual_termination", user_id: Any = None
    ) -> bool:
        """Hard-revoke a session: remove it from storage (and its user index).

        Passing ``user_id`` (known on the indexed terminate paths) lets the
        backend skip re-reading the record just to update its user index.
        """
        logger.debug("terminating session %s (reason=%s)", session_id, reason)
        return await self.storage.delete(session_id, user_id=user_id)

    async def terminate_all_user_sessions(
        self, user_id: Any, reason: str = "logout_all", exclude: str | None = None
    ) -> int:
        """Terminate every active session for ``user_id`` (optionally keeping ``exclude``).

        Returns:
            The number of sessions terminated. The public-facing wrapper is
            [revoke_all][crudauth.transports.session.manager.SessionManager.revoke_all].
        """
        terminated = 0
        for sid in await self._user_session_ids(user_id):
            if exclude is not None and sid == exclude:
                continue
            if await self.terminate_session(sid, reason=reason, user_id=user_id):
                terminated += 1
        return terminated

    # --- public device-management API (used by app endpoints) ----------------
    async def list_for_user(
        self, user_id: Any, current_session_id: str | None = None
    ) -> list[dict[str, Any]]:
        """List a user's active sessions for a "manage devices" UI.

        Args:
            user_id: Whose sessions to list.
            current_session_id: If given, the matching entry is flagged
                ``"current": True``.

        Returns:
            One dict per active session with ``session_id``, ``device``, ``ip``,
            ``created_at``, ``last_activity``, and ``current``. Empty if the
            storage backend can't index by user.

        Example:
            ```python
            @app.get("/account/sessions")
            async def sessions(user: Principal = Depends(auth.current_user())):
                return await auth.sessions.list_for_user(user.user_id)
            ```
        """
        out: list[dict[str, Any]] = []
        for sid in await self._user_session_ids(user_id):
            session = await self.storage.get(sid, SessionData)
            if session is None:
                continue
            out.append(
                {
                    "session_id": sid,
                    "device": session.device_info,
                    "ip": session.ip_address,
                    "created_at": session.created_at,
                    "last_activity": session.last_activity,
                    "current": sid == current_session_id,
                }
            )
        return out

    async def revoke(self, session_id: str, owner_id: Any | None = None) -> bool:
        """Revoke one session.

        Args:
            session_id: Session to revoke.
            owner_id: If given, the session is only revoked when it belongs to
                this user (so a user can't revoke someone else's session).

        Returns:
            ``True`` if a session was revoked, ``False`` if it didn't exist or
            failed the ownership check.
        """
        if owner_id is not None:
            session = await self.storage.get(session_id, SessionData)
            if session is None or session.user_id != owner_id:
                return False
        return await self.terminate_session(session_id, reason="user_revoked", user_id=owner_id)

    async def revoke_all(self, user_id: Any, exclude: str | None = None) -> int:
        """Revoke all of a user's sessions ("sign out everywhere").

        Args:
            user_id: Whose sessions to revoke.
            exclude: An optional session id to keep (e.g. the current one, for
                "sign out my other devices").

        Returns:
            The number of sessions revoked.
        """
        return await self.terminate_all_user_sessions(
            user_id, reason="user_revoked_all", exclude=exclude
        )

    # --- CSRF ----------------------------------------------------------------
    async def _generate_csrf_token(
        self, user_id: Any, session_id: str, expiration_seconds: int | None = None
    ) -> str:
        if self.csrf_storage is None:
            return ""
        ttl = (
            expiration_seconds
            if expiration_seconds is not None
            else int(self.session_timeout.total_seconds())
        )
        token = secrets.token_hex(self.csrf_token_bytes)
        csrf = CSRFToken(
            token=token,
            user_id=user_id,
            session_id=session_id,
            expiry=_utcnow() + timedelta(seconds=ttl),
        )
        await self.csrf_storage.create(csrf, session_id=token, expiration=ttl)
        return token

    async def regenerate_csrf_token(
        self, user_id: Any, session_id: str, expiration_seconds: int | None = None
    ) -> str:
        """Rotate the session's CSRF token and return the new one.

        Proper rotation, not just "issue another token": the new token is bound
        to the session (so [validate_session][crudauth.transports.session.manager.SessionManager.validate_session]
        slides *its* TTL, not the old one's), and the previous token is deleted
        so it can no longer pass [validate_csrf_token]
        [crudauth.transports.session.manager.SessionManager.validate_csrf_token].

        Returns the new token, or ``""`` when CSRF storage is disabled or the
        session no longer exists.
        """
        if self.csrf_storage is None:
            return ""
        session = await self.storage.get(session_id, SessionData)
        if session is None:
            return ""
        ttl = (
            expiration_seconds
            if expiration_seconds is not None
            else self.timeout_seconds_for(session.metadata)
        )
        old_token = session.metadata.get(CSRF_TOKEN_ID_META_KEY)
        new_token = await self._generate_csrf_token(user_id, session_id, ttl)
        session.metadata[CSRF_TOKEN_ID_META_KEY] = new_token
        await self.storage.update(session_id, session, expiration=ttl)
        if old_token:
            await self.csrf_storage.delete(old_token)
        return new_token

    async def validate_csrf_token(self, session_id: str, csrf_token: str) -> bool:
        """True if ``csrf_token`` is a live token bound to ``session_id``.

        Note:
            Expiry is governed solely by the storage TTL (which slides forward
            with the session - see [validate_session][crudauth.transports.session.manager.SessionManager.validate_session]); a present record is
            by definition a live token.
        """
        if self.csrf_storage is None:
            return True
        if not session_id or not csrf_token:
            return False
        data = await self.csrf_storage.get(csrf_token, CSRFToken)
        if data is None or data.session_id != session_id:
            return False
        return True

    # --- cookies -------------------------------------------------------------
    def set_session_cookies(
        self,
        response: Response,
        session_id: str,
        csrf_token: str,
        max_age: int | None = None,
    ) -> None:
        """Write the session + CSRF cookies.

        Note:
            ``max_age=None`` emits a *session cookie* (no ``Max-Age``) - the
            authoritative expiry is the server-side sliding idle check in
            [validate_session][crudauth.transports.session.manager.SessionManager.validate_session], so a fixed ``Max-Age`` would hard-expire a
            still-active session and defeat the slide. Remember-me passes an
            explicit long ``max_age`` for a persistent cookie whose lifetime
            matches its (equally long) server window.

        Note:
            The session cookie is ``httponly`` but the CSRF cookie is NOT - it
            must be readable by JS so the SPA can echo it in the ``X-CSRF-Token``
            header (the synchronizer-token check). Do not make it ``httponly``.
        """
        response.set_cookie(
            key=self.session_cookie_name,
            value=session_id,
            httponly=True,
            secure=self.cookie_secure,
            samesite=self.cookie_samesite,
            path=self.cookie_path,
            max_age=max_age,
        )
        if csrf_token:
            response.set_cookie(
                key=self.csrf_cookie_name,
                value=csrf_token,
                httponly=False,
                secure=self.cookie_secure,
                samesite=self.cookie_samesite,
                path=self.cookie_path,
                max_age=max_age,
            )

    def clear_session_cookies(self, response: Response) -> None:
        """Delete the session + CSRF cookies.

        Note:
            Deletes with the same ``secure``/``samesite`` as the set - some
            browsers only honor a deletion when those attributes match.
        """
        for name in (self.session_cookie_name, self.csrf_cookie_name):
            response.delete_cookie(
                name,
                path=self.cookie_path,
                secure=self.cookie_secure,
                samesite=self.cookie_samesite,
            )

    # --- session-limit enforcement & cleanup ---------------------------------
    async def _user_session_ids(self, user_id: Any) -> list[str]:
        """User's session ids, or ``[]`` when the backend can't index by user.

        Note:
            ``get_user_sessions`` is an optional storage capability; a backend
            that doesn't implement it disables multi-device limits and "sign out
            everywhere" rather than erroring.
        """
        try:
            return await self.storage.get_user_sessions(user_id)
        except NotImplementedError:
            return []
        except Exception as exc:  # pragma: no cover
            logger.warning("get_user_sessions failed: %s", exc)
            return []

    async def _enforce_session_limit(self, user_id: Any) -> None:
        ids = await self._user_session_ids(user_id)
        active: list[SessionData] = []
        for sid in ids:
            session = await self.storage.get(sid, SessionData)
            if session is not None:
                active.append(session)
        if len(active) >= self.max_sessions:
            active.sort(key=lambda s: s.last_activity)
            excess = len(active) - self.max_sessions + 1
            for session in active[:excess]:
                await self.terminate_session(
                    session.session_id, reason="session_limit", user_id=session.user_id
                )

    async def cleanup_expired_sessions(self, force: bool = False) -> None:
        """Proactively sweep idle-expired sessions (throttled by ``cleanup_interval``).

        Not called on the auth path: session TTL equals the idle window, so the
        storage backend evicts idle sessions on its own and ``validate_session``
        catches idle-on-read. This sweep is therefore optional - call it
        explicitly (e.g. ``force=True`` from an ops job) if a no-TTL BYO backend
        needs proactive pruning. Needs the storage's optional ``scan_keys``
        capability; a backend without it simply gets no sweep.

        Note:
            Login-lockout keys (``login:*``) are deliberately NOT swept - they
            carry their own TTLs (attempt window, lockout duration, round
            retention), and bulk-deleting them would clear live lockouts and
            reset the exponential-backoff escalation. Never pattern-delete the
            lockout keys here.
        """
        now = _utcnow()
        if not force and now - self.last_cleanup < self.cleanup_interval:
            return
        self.last_cleanup = now
        try:
            keys = await self.storage.scan_keys(f"{self.storage.prefix}*")
        except NotImplementedError:
            return
        except Exception as exc:  # pragma: no cover
            logger.warning("cleanup scan failed: %s", exc)
            return
        for key in keys:
            sid = key[len(self.storage.prefix) :] if key.startswith(self.storage.prefix) else key
            session = await self.storage.get(sid, SessionData)
            if session is not None and self._is_idle_expired(session, now):
                await self.terminate_session(sid, reason="session_timeout", user_id=session.user_id)

    # --- login lockout -------------------------------------------------------
    async def track_login_attempt(
        self, ip_address: str, username: str, success: bool = False
    ) -> tuple[bool, int | None, int]:
        """Record a login attempt and report whether it's allowed.

        Delegates to the injected [LockoutPolicy][crudauth.ratelimit.policy.LockoutPolicy].
        Fails open (allows) only when no policy is configured at all.

        Returns:
            ``(allowed, attempts_remaining, retry_after_seconds)``.
        """
        if self.lockout is None:
            return True, None, 0
        return await self.lockout.check_and_record(ip_address, username, success)

    # --- storage lifecycle ---------------------------------------------------
    async def initialize(self) -> None:
        """Open the session and CSRF storage connections."""
        await self.storage.initialize()
        if self.csrf_storage is not None:
            await self.csrf_storage.initialize()

    async def shutdown(self) -> None:
        """Close the session and CSRF storage connections."""
        await self.storage.close()
        if self.csrf_storage is not None:
            await self.csrf_storage.close()
