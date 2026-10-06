"""``SessionManager`` - server-side sessions, CSRF, lockout, device management.

Decoupled from any global settings: every policy knob is a constructor argument.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from collections.abc import Callable
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
        key_secret: str | None = None,
        absolute_timeout_hours: int | None = None,
    ):
        """Run sessions over ``session_storage``.

        Args:
            key_secret: When set, sessions and CSRF tokens are stored under an HMAC of
                their id keyed with it, and the raw id is never written, so whoever can
                read the store can't sign in with what they read. The session
                transport passes the app's ``SECRET_KEY``; changing it signs everyone
                out. ``None`` stores them under the raw id.
            absolute_timeout_hours: The most a session may live from its creation,
                however active it stays; ``None`` (default) leaves only the idle timeout.
        """
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
        self.key_secret = key_secret
        self.absolute_timeout = (
            timedelta(hours=absolute_timeout_hours) if absolute_timeout_hours is not None else None
        )

    # --- storage keys ----------------------------------------------------------
    def _keyed(self, purpose: bytes, value: str) -> str:
        if self.key_secret is None:
            return value
        return hmac.new(
            self.key_secret.encode(), purpose + value.encode(), hashlib.sha256
        ).hexdigest()

    def _key(self, session_id: str) -> str:
        """The storage key for a session id from a cookie."""
        return self._keyed(b"session:", session_id)

    def _csrf_key(self, token: str) -> str:
        """The storage key for a CSRF token from a header."""
        return self._keyed(b"csrf:", token)

    def _handle_of(self, key: str) -> str:
        """The public handle of a stored session: its key, which already can't be reversed."""
        if self.key_secret is None:
            return hashlib.sha256(key.encode()).hexdigest()
        return key

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
        token_version: int | None = None,
    ) -> tuple[str, str]:
        """Create a session + CSRF token. Returns ``(session_id, csrf_token)``.

        Args:
            request: The login request (user agent and client IP are recorded).
            user_id: The session's owner.
            metadata: Extra values stored on the session.
            expiration_seconds: TTL override; the idle window for ``metadata`` otherwise.
            token_version: The user's ``token_version`` when their credentials were
                checked. The session transport rejects the session once the user's
                version moves past it, so a password reset also revokes a session
                created after the reset from an earlier password check. ``None``
                leaves the session unbound.

        Note:
            The CSRF token id is stored on the session so its TTL can slide
            forward alongside the session in [validate_session][crudauth.transports.session.manager.SessionManager.validate_session].
        """
        user_agent = request.headers.get("user-agent", "")
        device_info = parse_user_agent(user_agent).model_dump()
        ip_address = get_client_ip(request, self.trusted_proxy_hops)

        presented = request.cookies.get(self.session_cookie_name)
        if presented:
            await self.terminate_session(presented, reason="replaced_by_login")
        await self._enforce_session_limit(user_id)

        session = SessionData(
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            device_info=device_info,
            metadata=metadata or {},
            token_version=token_version,
        )
        ttl = (
            expiration_seconds
            if expiration_seconds is not None
            else self.timeout_seconds_for(session.metadata)
        )
        session_id = session.session_id
        key = self._key(session_id)
        session.session_id = key
        csrf_token = await self._generate_csrf_token(key, ttl)
        if csrf_token:
            session.metadata[CSRF_TOKEN_ID_META_KEY] = self._csrf_key(csrf_token)
        await self.storage.create(session, session_id=key, expiration=ttl)
        return session_id, csrf_token

    async def validate_session(
        self, session_id: str, update_activity: bool = True
    ) -> SessionData | None:
        """Return the live session for ``session_id``, or ``None`` if invalid/idle-expired.

        Note:
            On activity, the CSRF token's TTL is slid forward together with the
            session's - otherwise it would expire out from under a session kept
            alive by activity and 403 later mutations.

        Note:
            The activity update goes through [modify][crudauth.storage.base.AbstractSessionStorage.modify]
            and sets only ``last_activity``, so a sudo stamp or a CSRF rotation
            written while this request was in flight is kept.
        """
        if not session_id:
            return None
        key = self._key(session_id)
        session = await self.storage.get(key, SessionData)
        if session is None:
            return None
        now = _utcnow()
        if self._is_idle_expired(session, now):
            await self._terminate(key, session, reason="session_timeout")
            return None
        if self.absolute_timeout is not None and session.created_at < now - self.absolute_timeout:
            await self._terminate(key, session, reason="session_absolute_timeout")
            return None
        if not update_activity:
            return session

        def touch(current: SessionData) -> None:
            current.last_activity = now

        ttl = self.timeout_seconds_for(session.metadata)
        touched = await self.storage.modify(key, SessionData, touch, expiration=ttl)
        if touched is None:
            return None
        csrf_id = touched.metadata.get(CSRF_TOKEN_ID_META_KEY)
        if csrf_id and self.csrf_storage is not None:
            await self.csrf_storage.extend(csrf_id, ttl)
        return touched

    async def set_token_version(self, session_id: str, token_version: int) -> bool:
        """Rebind a live session to the user's current ``token_version``.

        For a credential change that keeps the caller signed in: bump the user's
        version, then rebind the caller's session so only the others are revoked.

        Returns:
            ``True`` if the session exists and was rebound.
        """

        def rebind(current: SessionData) -> None:
            current.token_version = token_version

        return await self.modify_session(session_id, rebind) is not None

    async def get_session(self, session_id: str) -> SessionData | None:
        """The stored session for a session id from a cookie, without touching its activity."""
        return await self.storage.get(self._key(session_id), SessionData)

    async def modify_session(
        self, session_id: str, change: Callable[[SessionData], None]
    ) -> SessionData | None:
        """Apply ``change`` to a live session without moving its expiry.

        For values stored on the session (a sudo stamp, a rebound ``token_version``):
        ``change`` may run more than once under a concurrent write, so it must only
        set values. Returns the updated session, or ``None`` if it no longer exists.
        """
        return await self.storage.modify(
            self._key(session_id), SessionData, change, reset_expiration=False
        )

    async def terminate_session(self, session_id: str, reason: str = "manual_termination") -> bool:
        """Hard-revoke a session: remove it, its user-index entry, and its CSRF token.

        Returns:
            ``True`` if a session was removed.
        """
        key = self._key(session_id)
        session = await self.storage.get(key, SessionData)
        if session is None:
            return False
        return await self._terminate(key, session, reason)

    async def _terminate(self, key: str, session: SessionData, reason: str) -> bool:
        logger.debug("terminating session %s (reason=%s)", self._handle_of(key), reason)
        deleted = await self.storage.delete(key, user_id=session.user_id)
        csrf_id = session.metadata.get(CSRF_TOKEN_ID_META_KEY)
        if csrf_id and self.csrf_storage is not None:
            await self.csrf_storage.delete(csrf_id)
        return deleted

    async def terminate_all_user_sessions(
        self, user_id: Any, reason: str = "logout_all", exclude: str | None = None
    ) -> int:
        """Terminate every active session for ``user_id`` (optionally keeping ``exclude``).

        Returns:
            The number of sessions terminated. The public-facing wrapper is
            [revoke_all][crudauth.transports.session.manager.SessionManager.revoke_all].
        """
        terminated = 0
        excluded = self._key(exclude) if exclude else None
        for sid, session in await self._user_sessions(user_id):
            if sid != excluded and await self._terminate(sid, session, reason):
                terminated += 1
        return terminated

    # --- public device-management API (used by app endpoints) ----------------
    def session_handle(self, session_id: str) -> str:
        """The public handle for a session: the key it's stored under, an HMAC of its id.

        The session id is the cookie value, so it must never reach a page or an
        API response. A handle identifies the session in a device list and can be
        passed to [revoke_by_handle][crudauth.transports.session.manager.SessionManager.revoke_by_handle],
        but it can't be turned back into a cookie. Without a ``key_secret`` it's the
        SHA-256 hex digest of the id.
        """
        return self._handle_of(self._key(session_id))

    async def list_for_user(
        self, user_id: Any, current_session_id: str | None = None
    ) -> list[dict[str, Any]]:
        """List a user's active sessions for a "manage devices" UI.

        Args:
            user_id: Whose sessions to list.
            current_session_id: If given, the matching entry is flagged
                ``"current": True``.

        Returns:
            One dict per active session with ``id`` (the
            [session_handle][crudauth.transports.session.manager.SessionManager.session_handle],
            never the session id), ``device``, ``ip``, ``created_at``,
            ``last_activity``, and ``current``. Empty if the storage backend can't
            index by user.

        Example:
            ```python
            @app.get("/account/sessions")
            async def sessions(user: Principal = Depends(auth.current_user())):
                return await auth.sessions.list_for_user(user.user_id)
            ```
        """
        out: list[dict[str, Any]] = []
        current = self._key(current_session_id) if current_session_id else None
        for sid, session in await self._user_sessions(user_id):
            out.append(
                {
                    "id": self._handle_of(sid),
                    "device": session.device_info,
                    "ip": session.ip_address,
                    "created_at": session.created_at,
                    "last_activity": session.last_activity,
                    "current": sid == current,
                }
            )
        return out

    async def revoke(self, session_id: str, owner_id: Any | None = None) -> bool:
        """Revoke one session.

        Args:
            session_id: Session to revoke.
            owner_id: If given, the session is only revoked when it belongs to
                this user (so a user can't revoke someone else's session). Compared
                as a string, the way the stored ``user_id`` round-trips.

        Returns:
            ``True`` if a session was revoked, ``False`` if it didn't exist or
            failed the ownership check.
        """
        key = self._key(session_id)
        session = await self.storage.get(key, SessionData)
        if session is None or (owner_id is not None and str(session.user_id) != str(owner_id)):
            return False
        return await self._terminate(key, session, reason="user_revoked")

    async def revoke_by_handle(self, handle: str, owner_id: Any) -> bool:
        """Revoke one of ``owner_id``'s sessions by its public handle.

        Args:
            handle: A [session_handle][crudauth.transports.session.manager.SessionManager.session_handle],
                as listed by [list_for_user][crudauth.transports.session.manager.SessionManager.list_for_user].
            owner_id: Whose sessions the handle is looked up among.

        Returns:
            ``True`` if a session was revoked, ``False`` if none of the owner's
            sessions has that handle (or the backend can't index by user).
        """
        for sid, session in await self._user_sessions(owner_id):
            if hmac.compare_digest(self._handle_of(sid), handle):
                return await self._terminate(sid, session, reason="user_revoked")
        return False

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
    async def _generate_csrf_token(self, key: str, expiration_seconds: int | None = None) -> str:
        """Issue a CSRF token bound to the session stored under ``key``; returns the raw token."""
        if self.csrf_storage is None:
            return ""
        ttl = (
            expiration_seconds
            if expiration_seconds is not None
            else int(self.session_timeout.total_seconds())
        )
        token = secrets.token_hex(self.csrf_token_bytes)
        token_key = self._csrf_key(token)
        csrf = CSRFToken(
            token=token_key,
            session_id=key,
            expiry=_utcnow() + timedelta(seconds=ttl),
        )
        await self.csrf_storage.create(csrf, session_id=token_key, expiration=ttl)
        return token

    async def regenerate_csrf_token(
        self, session_id: str, expiration_seconds: int | None = None
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
        key = self._key(session_id)
        session = await self.storage.get(key, SessionData)
        if session is None:
            return ""
        ttl = (
            expiration_seconds
            if expiration_seconds is not None
            else self.timeout_seconds_for(session.metadata)
        )
        new_token = await self._generate_csrf_token(key, ttl)
        new_key = self._csrf_key(new_token)
        replaced = ""

        def rotate(current: SessionData) -> None:
            nonlocal replaced
            replaced = current.metadata.get(CSRF_TOKEN_ID_META_KEY) or ""
            current.metadata[CSRF_TOKEN_ID_META_KEY] = new_key

        if await self.storage.modify(key, SessionData, rotate, expiration=ttl) is None:
            await self.csrf_storage.delete(new_key)
            return ""
        if replaced:
            await self.csrf_storage.delete(replaced)
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
        data = await self.csrf_storage.get(self._csrf_key(csrf_token), CSRFToken)
        if data is None or not hmac.compare_digest(data.session_id, self._key(session_id)):
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
        self.set_csrf_cookie(response, csrf_token, max_age=max_age)

    def set_csrf_cookie(
        self, response: Response, csrf_token: str, max_age: int | None = None
    ) -> None:
        """Write just the CSRF cookie (used on its own by the ``/csrf/refresh`` recovery path).

        Note:
            NOT ``httponly`` - the CSRF cookie must be readable by JS so the SPA
            can echo it in the ``X-CSRF-Token`` header (the synchronizer-token
            check). Same ``secure``/``samesite``/``path`` as the session cookie so
            the pair can't disagree. A falsy ``csrf_token`` is a no-op.
        """
        if not csrf_token:
            return
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
    async def _user_sessions(self, user_id: Any) -> list[tuple[str, SessionData]]:
        """The user's live ``(session_id, session)`` pairs, pruning index entries whose record is gone."""
        sessions: list[tuple[str, SessionData]] = []
        for sid in await self._user_session_ids(user_id):
            session = await self.storage.get(sid, SessionData)
            if session is None:
                await self.storage.remove_from_user_index(user_id, sid)
            else:
                sessions.append((sid, session))
        return sessions

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
        active = await self._user_sessions(user_id)
        if len(active) >= self.max_sessions:
            active.sort(key=lambda pair: pair[1].last_activity)
            excess = len(active) - self.max_sessions + 1
            for sid, session in active[:excess]:
                await self._terminate(sid, session, reason="session_limit")

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
                await self._terminate(sid, session, reason="session_timeout")

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
