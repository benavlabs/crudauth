"""The session transport: cookie auth with CSRF, lockout, and device management.

This is the default transport - configuring nothing gives you cookie sessions,
CSRF synchronizer-token, login lockout, secure cookies, and ``/login`` ``/logout``.
"""

import logging
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.security import OAuth2PasswordRequestForm

from ...constants import (
    DEFAULT_CLEANUP_INTERVAL_MINUTES,
    DEFAULT_LOGIN_ATTEMPT_WINDOW_SECONDS,
    DEFAULT_LOGIN_LOCKOUT_BASE_SECONDS,
    DEFAULT_LOGIN_LOCKOUT_MAX_SECONDS,
    DEFAULT_LOGIN_MAX_ATTEMPTS,
    DEFAULT_MAX_SESSIONS_PER_USER,
    DEFAULT_REMEMBER_ME_DAYS,
    DEFAULT_SESSION_TIMEOUT_MINUTES,
    SECONDS_PER_MINUTE,
)
from ...core import AuthContext, AuthRuntime, CookieConfig, Transport
from ...exceptions import CSRFException, RateLimitException, UnauthorizedException
from ...hooks import HookContext
from ...principal import Principal
from ...storage import get_session_storage
from ...storage.constants import BACKEND_MEMORY
from ...utils import (
    canonical_identifier,
    dummy_verify_password,
    get_client_ip,
    verify_password,
)
from .constants import (
    CSRF_HEADER_NAME,
    CSRF_STORAGE_PREFIX,
    REMEMBER_ME_META_KEY,
    SAFE_METHODS,
    SESSION_STORAGE_PREFIX,
)
from .manager import SessionManager
from .schemas import SessionData

__all__ = ["SessionTransport"]

logger = logging.getLogger("crudauth.session")


class SessionTransport(Transport):
    """Cookie-based session auth - the default transport.

    Configuring nothing gives cookie sessions, CSRF synchronizer-token (header-only),
    login lockout, secure cookies, and ``/login`` ``/logout``. CSRF is enforced
    inside [authenticate][crudauth.core.Transport.authenticate] on unsafe methods; the session cookie is never
    ``SameSite=None`` (rejected at construction).

    Args:
        backend: ``"memory"`` (default) or ``"redis"`` for shared/persistent state.
        redis_url: Connection URL when ``backend="redis"``.
        csrf: Enforce the synchronizer-token header on unsafe methods (default ``True``).
        cookies: Per-transport [CookieConfig][crudauth.core.CookieConfig] override.
        login_max_attempts: Failed logins before the escalating lockout trips.
        on_login_success: What a successful login clears - ``"clear_all"`` (default)
            or ``"clear_user_only"`` (keeps per-IP pressure; only safe when the
            per-IP key identifies an individual client, not a shared NAT/CGNAT
            egress). Governs the shared lockout (both ``/login`` and ``/token``).
            See [LockoutPolicy][crudauth.ratelimit.policy.LockoutPolicy].

    Example:
        ```python
        CRUDAuth(
            session=get_session, user_model=User, SECRET_KEY=...,
            transports=[SessionTransport(backend="redis", redis_url=..., csrf=True)],
        )
        ```
    """

    name = "session"

    def __init__(
        self,
        *,
        backend: str = BACKEND_MEMORY,
        redis_url: str | None = None,
        csrf: bool = True,
        max_sessions_per_user: int = DEFAULT_MAX_SESSIONS_PER_USER,
        session_timeout_minutes: int = DEFAULT_SESSION_TIMEOUT_MINUTES,
        remember_me_days: int = DEFAULT_REMEMBER_ME_DAYS,
        cleanup_interval_minutes: int = DEFAULT_CLEANUP_INTERVAL_MINUTES,
        cookies: CookieConfig | None = None,
        login_max_attempts: int = DEFAULT_LOGIN_MAX_ATTEMPTS,
        login_attempt_window_seconds: int = DEFAULT_LOGIN_ATTEMPT_WINDOW_SECONDS,
        login_lockout_base_seconds: int = DEFAULT_LOGIN_LOCKOUT_BASE_SECONDS,
        login_lockout_max_seconds: int = DEFAULT_LOGIN_LOCKOUT_MAX_SECONDS,
        on_login_success: Literal["clear_all", "clear_user_only"] = "clear_all",
    ):
        self.backend = backend
        self.redis_url = redis_url
        self.csrf_enabled = csrf
        self.max_sessions_per_user = max_sessions_per_user
        self.session_timeout_minutes = session_timeout_minutes
        self.remember_me_days = remember_me_days
        self.cleanup_interval_minutes = cleanup_interval_minutes
        self._cookie_override = cookies
        self.login_max_attempts = login_max_attempts
        self.login_attempt_window_seconds = login_attempt_window_seconds
        self.login_lockout_base_seconds = login_lockout_base_seconds
        self.login_lockout_max_seconds = login_lockout_max_seconds
        self.on_login_success = on_login_success
        self.manager: SessionManager | None = None

    # --- wiring --------------------------------------------------------------
    def bind(self, runtime: AuthRuntime) -> None:
        """Build the [SessionManager][crudauth.transports.session.manager.SessionManager] from the bound runtime.

        Note:
            Rejects ``SameSite=None`` for the session cookie at config time.
            SameSite is the backstop the header-only CSRF check leans on (the
            cookie auto-rides cross-origin, the header doesn't); ``none`` removes
            it and silently weakens CSRF. Bearer cookies *may* be ``none`` (no
            CSRF surface), so this guard is session-transport-specific.

        Note:
            Login lockout is the shared ``runtime.lockout`` (the same policy the
            bearer ``/token`` route uses), so the two endpoints can't sidestep
            each other's counter.
        """
        super().bind(runtime)
        cookies = self.cookie_config()
        if cookies.samesite == "none":
            raise ValueError(
                "SessionTransport cookies cannot use SameSite=None (it weakens CSRF "
                "protection). Use 'lax' or 'strict'."
            )
        timeout_seconds = self.session_timeout_minutes * SECONDS_PER_MINUTE
        session_storage = get_session_storage(
            self.backend,
            prefix=SESSION_STORAGE_PREFIX,
            expiration=timeout_seconds,
            redis_url=self.redis_url,
        )
        csrf_storage = None
        if self.csrf_enabled:
            csrf_storage = get_session_storage(
                self.backend,
                prefix=CSRF_STORAGE_PREFIX,
                expiration=timeout_seconds,
                redis_url=self.redis_url,
            )

        self.manager = SessionManager(
            session_storage,
            csrf_storage=csrf_storage,
            max_sessions_per_user=self.max_sessions_per_user,
            session_timeout_minutes=self.session_timeout_minutes,
            remember_me_days=self.remember_me_days,
            cleanup_interval_minutes=self.cleanup_interval_minutes,
            lockout=runtime.lockout,
            cookie_secure=cookies.secure,
            cookie_samesite=cookies.samesite,
            cookie_path=cookies.path,
            trusted_proxy_hops=runtime.trusted_proxy_hops,
        )

    async def initialize(self) -> None:
        """Open the session manager's storage connections."""
        if self.manager is not None:
            await self.manager.initialize()

    async def shutdown(self) -> None:
        """Close the session manager's storage connections."""
        if self.manager is not None:
            await self.manager.shutdown()

    # --- authn ---------------------------------------------------------------
    async def authenticate(self, request: Request, ctx: AuthContext) -> Principal | None:
        """Authenticate via the session cookie.

        Returns ``None`` when no session cookie is present or the session is
        invalid/idle-expired (try the next transport). On a present, valid
        session it enforces CSRF for unsafe methods (raising on failure) and
        returns the [Principal][crudauth.principal.Principal].
        """
        assert self.manager is not None
        session_id = request.cookies.get(self.manager.session_cookie_name)
        if not session_id:
            return None

        session = await self.manager.validate_session(session_id)
        if session is None:
            return None

        await self._enforce_csrf(request, session_id)

        user = await ctx.resolve_user(session.user_id)
        if user is None or not ctx.repo.is_active(user):
            return None
        return ctx.build_principal(
            user_id=ctx.repo.user_id(user),
            user=user,
            transport=self.name,
            scopes=(),
            metadata={"session_id": session_id},
        )

    async def _enforce_csrf(self, request: Request, session_id: str) -> None:
        """Require a valid synchronizer-token header on unsafe methods.

        Note:
            Header-only by design: the ``csrf_token`` cookie auto-rides
            cross-origin requests but a custom header does not, so requiring the
            header (not just the cookie) is what makes the synchronizer-token check
            load-bearing. Safe methods (GET/HEAD/OPTIONS) are exempt.
        """
        if not self.csrf_enabled or request.method in SAFE_METHODS:
            return
        assert self.manager is not None
        header = request.headers.get(CSRF_HEADER_NAME)
        if not header:
            raise CSRFException("Missing CSRF token")
        if not await self.manager.validate_csrf_token(session_id, header):
            raise CSRFException("Invalid CSRF token")

    # --- routes --------------------------------------------------------------
    def contributes_routes(self) -> APIRouter:
        router = APIRouter(tags=["auth"])
        runtime = self.runtime
        db_dep = runtime.db_dependency

        @router.post("/login")
        async def login(
            request: Request,
            response: Response,
            form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
            db: Annotated[Any, Depends(db_dep)],
            remember_me: Annotated[bool, Form()] = False,
        ):
            """Log in with username/email + password; sets the session + CSRF cookies.

            Subject to login lockout (shared with bearer ``/token``). ``remember_me``
            switches the cookie from session-scoped to a long persistent lifetime.

            Note:
                A disabled account returns the same "Incorrect username or
                password" as bad credentials, so a credential holder can't tell a
                disabled account from a wrong password; the real reason is logged
                server-side (``reason=disabled``) for operators.
            """
            assert self.manager is not None
            ip = get_client_ip(request, runtime.trusted_proxy_hops)
            login_id = canonical_identifier(form_data.username)
            allowed, _, retry_after = await self.manager.track_login_attempt(
                ip, login_id, success=False
            )
            if not allowed:
                raise RateLimitException(
                    "Too many login attempts. Try again later.", retry_after=retry_after
                )

            user = await runtime.repo.resolve_login(db, form_data.username)
            if user is None:
                dummy_verify_password(form_data.password)
                raise UnauthorizedException("Incorrect username or password")
            if not verify_password(
                form_data.password, runtime.repo.get(user, "hashed_password", "")
            ):
                raise UnauthorizedException("Incorrect username or password")
            if not runtime.repo.is_active(user):
                logger.warning(
                    "login denied: account disabled (user_id=%s)", runtime.repo.user_id(user)
                )
                raise UnauthorizedException("Incorrect username or password")

            await self.manager.track_login_attempt(ip, login_id, success=True)

            metadata = {REMEMBER_ME_META_KEY: True} if remember_me else {}
            session_id, csrf = await self.manager.create_session(
                request, user_id=runtime.repo.user_id(user), metadata=metadata
            )
            cookie_max_age = self.manager.timeout_seconds_for(metadata) if remember_me else None
            self.manager.set_session_cookies(response, session_id, csrf, max_age=cookie_max_age)

            await runtime.hooks.run_after_login(
                runtime.repo.to_dict(user),
                request=request,
                context=HookContext(
                    ip_address=ip,
                    user_agent=request.headers.get("user-agent"),
                    transport=self.name,
                    request=request,
                ),
            )
            return {
                "id": runtime.repo.user_id(user),
                "username": runtime.repo.get(user, "username"),
                "csrf_token": csrf,
            }

        @router.post("/logout")
        async def logout(request: Request, response: Response, db: Annotated[Any, Depends(db_dep)]):
            """Revoke the current session and clear its cookies (CSRF-protected)."""
            assert self.manager is not None
            session_id = request.cookies.get(self.manager.session_cookie_name)
            user_dict = None
            if session_id:
                await self._enforce_csrf(request, session_id)
                session = await self.manager.storage.get(session_id, SessionData)
                if session is not None:
                    user = await runtime.repo.get_by_id(db, session.user_id)
                    if user is not None:
                        user_dict = runtime.repo.to_dict(user)
                await self.manager.terminate_session(session_id, reason="logout")
            self.manager.clear_session_cookies(response)
            if user_dict is not None:
                await runtime.hooks.run_after_logout(
                    user_dict,
                    request=request,
                    context=HookContext(transport=self.name, request=request),
                )
            return {"detail": "Logged out"}

        return router
