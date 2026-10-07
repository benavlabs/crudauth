"""The session transport: cookie auth with CSRF, lockout, and device management.

This is the default transport - configuring nothing gives you cookie sessions,
CSRF synchronizer-token, login lockout, secure cookies, and ``/login`` ``/logout``.
"""

from typing import Any

from fastapi import APIRouter, Request, Response

from ...constants import (
    DEFAULT_CLEANUP_INTERVAL_MINUTES,
    DEFAULT_MAX_SESSIONS_PER_USER,
    DEFAULT_REMEMBER_ME_DAYS,
    DEFAULT_SESSION_TIMEOUT_MINUTES,
    SECONDS_PER_MINUTE,
)
from ...core import AuthContext, AuthRuntime, CookieConfig, Transport
from ...exceptions import CSRFException
from ...hooks import HookContext
from ...principal import Principal
from ...ratelimit.config import LockoutConfig, LoginSuccessClears
from ...storage import get_session_storage
from ...storage.base import AbstractSessionStorage
from ...storage.backends.redis import redis_client_from_url
from ...storage.constants import BACKEND_CUSTOM, BACKEND_DATABASE, BACKEND_MEMORY, BACKEND_REDIS
from ...utils import get_client_ip
from .constants import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    CSRF_STORAGE_PREFIX,
    REMEMBER_ME_META_KEY,
    SAFE_METHODS,
    SESSION_COOKIE_NAME,
    SESSION_STORAGE_PREFIX,
)
from .manager import SessionManager
from .routes import build_session_routes
from .schemas import CSRFToken, SessionData

__all__ = ["SessionTransport"]


class SessionTransport(Transport):
    """Cookie-based session auth - the default transport.

    Configuring nothing gives cookie sessions, CSRF synchronizer-token (header-only),
    login lockout, secure cookies, and ``/login`` ``/logout``. CSRF is enforced
    inside [authenticate][crudauth.core.Transport.authenticate] on unsafe methods; the session cookie is never
    ``SameSite=None`` (rejected at construction).

    Args:
        backend: Where sessions and CSRF tokens live, ``"memory"``, ``"redis"`` or
            ``"database"``. Left unset, it's Redis when this transport or
            [CRUDAuth][crudauth.crud_auth.CRUDAuth] has a ``redis_url`` or ``redis_client``,
            the database when ``CRUDAuth`` has a ``database_store``, and memory otherwise.
        redis_url: Redis URL for this transport's sessions and CSRF tokens, overriding
            ``CRUDAuth``'s. The transport opens one client for it and closes it on shutdown.
        redis_client: Existing async Redis client for this transport, overriding
            ``CRUDAuth``'s. The caller owns it, so ``auth.shutdown()`` doesn't close it.
            Mutually exclusive with ``redis_url``.
        csrf: Enforce the synchronizer-token header on unsafe methods (default ``True``).
        absolute_timeout_hours: The most a session may live from sign-in, however active it
            stays. ``None`` (default) leaves only the idle timeout, so a session kept busy
            never ends; set it to force a periodic re-login.
        cookies: Per-transport [CookieConfig][crudauth.core.CookieConfig] override.
        cookie_name: The session cookie's name (default ``"session_id"``).
        csrf_cookie_name: The CSRF cookie's name (default ``"csrf_token"``).
        storage_prefix: The key prefix sessions are stored under (default ``"session:"``).
        csrf_storage_prefix: The key prefix CSRF tokens are stored under (default ``"csrf:"``).
            Two apps that each run crudauth must not share all four: on one Redis, the same
            prefix lets one app's session id resolve in the other, and in one browser the same
            cookie name lets the second login overwrite the first. Give an embedded app (an
            admin panel mounted beside the main app) its own, e.g.
            ``SessionTransport(cookie_name="admin_session", csrf_cookie_name="admin_csrf",
            storage_prefix="admin:session:", csrf_storage_prefix="admin:csrf:")``.
        storage: A session store you built, instead of the memory or Redis one this
            transport would make: any [AbstractSessionStorage][crudauth.storage.base.AbstractSessionStorage]
            of [SessionData][crudauth.transports.session.schemas.SessionData] (a database
            table, Memcached, ...). It carries its own key prefix and expiration, so it can't be
            combined with ``backend``, ``redis_url``, ``redis_client`` or ``storage_prefix``.
            ``auth.initialize()`` and ``auth.shutdown()`` open and close it like the built-in ones.
        csrf_storage: The matching store of [CSRFToken][crudauth.transports.session.schemas.CSRFToken]
            rows, required with ``storage`` while ``csrf`` is on.
        login_max_attempts: The login lockout's ``max_attempts``.
        login_attempt_window_seconds: The login lockout's ``attempt_window_seconds``.
        login_lockout_base_seconds: The login lockout's ``lockout_base_seconds``.
        login_lockout_max_seconds: The login lockout's ``lockout_max_seconds``.
        on_login_success: The login lockout's ``on_login_success``. These ``login_*``
            arguments tune the lockout shared by ``/login`` and ``/token``; any left
            unset keeps the [LockoutConfig][crudauth.ratelimit.config.LockoutConfig]
            default. ``CRUDAuth(lockout=LockoutConfig(...))`` sets the same values
            without needing a session transport; setting both raises ``ValueError``.
        management_routes: When ``True``, mount the opt-in session/CSRF management
            routes on the shared router: ``POST /logout-all``, ``GET /sessions``,
            ``DELETE /sessions/{id}``, and ``POST /csrf/refresh``. Default ``False``
            (adding routes is a choice, and a device list isn't universally wanted).

    Example:
        ```python
        CRUDAuth(
            session=get_session, user_model=User, SECRET_KEY=...,
            redis_url=...,
            transports=[SessionTransport(session_timeout_minutes=30, csrf=True)],
        )
        ```
    """

    name = "session"

    def __init__(
        self,
        *,
        backend: str | None = None,
        redis_url: str | None = None,
        redis_client: Any = None,
        csrf: bool = True,
        max_sessions_per_user: int = DEFAULT_MAX_SESSIONS_PER_USER,
        session_timeout_minutes: int = DEFAULT_SESSION_TIMEOUT_MINUTES,
        absolute_timeout_hours: int | None = None,
        remember_me_days: int = DEFAULT_REMEMBER_ME_DAYS,
        cleanup_interval_minutes: int = DEFAULT_CLEANUP_INTERVAL_MINUTES,
        cookies: CookieConfig | None = None,
        cookie_name: str = SESSION_COOKIE_NAME,
        csrf_cookie_name: str = CSRF_COOKIE_NAME,
        storage_prefix: str = SESSION_STORAGE_PREFIX,
        csrf_storage_prefix: str = CSRF_STORAGE_PREFIX,
        storage: AbstractSessionStorage[SessionData] | None = None,
        csrf_storage: AbstractSessionStorage[CSRFToken] | None = None,
        login_max_attempts: int | None = None,
        login_attempt_window_seconds: int | None = None,
        login_lockout_base_seconds: int | None = None,
        login_lockout_max_seconds: int | None = None,
        on_login_success: LoginSuccessClears | None = None,
        management_routes: bool = False,
    ):
        if redis_url is not None and redis_client is not None:
            raise ValueError("redis_url and redis_client are mutually exclusive")
        if cookie_name == csrf_cookie_name:
            raise ValueError("cookie_name and csrf_cookie_name must differ")
        if storage_prefix == csrf_storage_prefix:
            raise ValueError("storage_prefix and csrf_storage_prefix must differ")
        if storage is not None:
            if backend is not None or redis_url is not None or redis_client is not None:
                raise ValueError(
                    "storage can't be combined with backend, redis_url or redis_client: "
                    "the store you pass decides where sessions live"
                )
            if storage_prefix != SESSION_STORAGE_PREFIX:
                raise ValueError("storage carries its own key prefix; drop storage_prefix")
            if csrf and csrf_storage is None:
                raise ValueError("storage needs a csrf_storage while csrf is on")
        elif csrf_storage is not None:
            raise ValueError("csrf_storage is only used together with storage")
        backend = backend.lower() if backend else None
        if backend in (BACKEND_MEMORY, BACKEND_DATABASE) and (
            redis_url is not None or redis_client is not None
        ):
            raise ValueError(
                f"backend={backend!r} can't be combined with redis_url or redis_client"
            )
        self._backend = backend
        self._redis_url = redis_url
        self._redis_client = redis_client
        self.backend = backend
        self.redis_url = redis_url
        self.redis_client = redis_client
        self._owned_client: Any = None
        self.csrf_enabled = csrf
        self.max_sessions_per_user = max_sessions_per_user
        self.session_timeout_minutes = session_timeout_minutes
        self.absolute_timeout_hours = absolute_timeout_hours
        self.remember_me_days = remember_me_days
        self.cleanup_interval_minutes = cleanup_interval_minutes
        self._cookie_override = cookies
        self.cookie_name = cookie_name
        self.csrf_cookie_name = csrf_cookie_name
        self.storage_prefix = storage_prefix
        self.csrf_storage_prefix = csrf_storage_prefix
        self._storage = storage
        self._csrf_storage = csrf_storage
        lockout_overrides: dict[str, Any] = {
            "max_attempts": login_max_attempts,
            "attempt_window_seconds": login_attempt_window_seconds,
            "lockout_base_seconds": login_lockout_base_seconds,
            "lockout_max_seconds": login_lockout_max_seconds,
            "on_login_success": on_login_success,
        }
        overrides = {name: value for name, value in lockout_overrides.items() if value is not None}
        self.lockout: LockoutConfig | None = LockoutConfig(**overrides) if overrides else None
        self.management_routes = management_routes
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
        if self._storage is not None:
            self.backend, self.redis_client = BACKEND_CUSTOM, None
            self.manager = self._build_manager(
                runtime, cookies, self._storage, self._csrf_storage if self.csrf_enabled else None
            )
            return
        client = self._redis_client
        if client is None and self._redis_url is not None:
            client = self._owned_client = redis_client_from_url(self._redis_url)
        elif client is None and self._backend not in (BACKEND_MEMORY, BACKEND_DATABASE):
            client = runtime.redis_client
        database = runtime.database_store if client is None else None
        if self._backend == BACKEND_DATABASE and database is None:
            raise ValueError("backend='database' needs CRUDAuth(database_store=...)")
        backend = self._backend or (
            BACKEND_REDIS
            if client is not None
            else BACKEND_DATABASE
            if database is not None
            else BACKEND_MEMORY
        )
        if backend == BACKEND_REDIS and client is None:
            client = self._owned_client = redis_client_from_url()
        self.backend, self.redis_client = backend, client
        session_storage: AbstractSessionStorage[SessionData] = get_session_storage(
            self.backend,
            prefix=self.storage_prefix,
            expiration=timeout_seconds,
            client=self.redis_client,
            database=database,
        )
        csrf_storage: AbstractSessionStorage[CSRFToken] | None = None
        if self.csrf_enabled:
            csrf_storage = get_session_storage(
                self.backend,
                prefix=self.csrf_storage_prefix,
                expiration=timeout_seconds,
                client=self.redis_client,
                database=database,
            )
        self.manager = self._build_manager(runtime, cookies, session_storage, csrf_storage)

    def _build_manager(
        self,
        runtime: AuthRuntime,
        cookies: CookieConfig,
        session_storage: AbstractSessionStorage[SessionData],
        csrf_storage: AbstractSessionStorage[CSRFToken] | None,
    ) -> SessionManager:
        return SessionManager(
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
            session_cookie_name=self.cookie_name,
            csrf_cookie_name=self.csrf_cookie_name,
            trusted_proxy_hops=runtime.trusted_proxy_hops,
            key_secret=runtime.secret_key,
            absolute_timeout_hours=self.absolute_timeout_hours,
        )

    async def initialize(self) -> None:
        """Open the session manager's storage connections."""
        if self.manager is not None:
            await self.manager.initialize()

    async def shutdown(self) -> None:
        """Close the session manager's storage connections, and the client built from ``redis_url``."""
        if self.manager is not None:
            await self.manager.shutdown()
        if self._owned_client is not None:
            await self._owned_client.aclose()

    # --- authn ---------------------------------------------------------------
    async def authenticate(self, request: Request, ctx: AuthContext) -> Principal | None:
        """Authenticate via the session cookie.

        Returns ``None`` when no session cookie is present or the session is
        invalid/idle-expired (try the next transport). On a present, valid
        session it enforces CSRF for unsafe methods (raising on failure) and
        returns the [Principal][crudauth.principal.Principal]. A session bound to
        a ``token_version`` the user has since moved past (a password reset or
        change) also returns ``None``.
        """
        assert self.manager is not None
        session_id = request.cookies.get(self.manager.session_cookie_name)
        if not session_id:
            return None

        session = await self.manager.validate_session(
            session_id, update_activity=ctx.update_activity
        )
        if session is None:
            return None

        if ctx.enforce_csrf:
            await self.enforce_csrf(request, session_id)

        user = await ctx.resolve_user(session.user_id)
        if user is None or not ctx.repo.is_active(user):
            return None
        if session.token_version not in (None, ctx.repo.token_version(user)):
            return None
        return ctx.build_principal(
            user_id=ctx.repo.user_id(user),
            user=user,
            transport=self.name,
            scopes=(),
            metadata={"session_id": session_id},
        )

    async def revalidate(self, request: Request, principal: Principal, ctx: AuthContext) -> bool:
        """Slide the session and enforce CSRF when an earlier resolution in this request skipped them."""
        assert self.manager is not None
        session_id = principal.metadata.get("session_id")
        if not session_id:
            return True
        if ctx.update_activity and await self.manager.validate_session(session_id) is None:
            return False
        if ctx.enforce_csrf:
            await self.enforce_csrf(request, session_id)
        return True

    async def enforce_csrf(self, request: Request, session_id: str) -> None:
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

    @property
    def sets_cookies(self) -> bool:
        return True

    async def complete_login(
        self, request: Request, response: Response, user: Any, options: dict[str, Any]
    ) -> dict[str, Any]:
        """Create the session, set its cookies, and fire ``on_after_login``.

        ``options``: ``remember_me`` for a persistent cookie, and ``metadata`` stored
        on the session (an OAuth login passes ``login_type="oauth"``, which is also
        the hook's ``transport``).

        Returns:
            ``{"id", "username", "csrf_token"}``.
        """
        assert self.manager is not None
        runtime = self.runtime
        remember_me = bool(options.get("remember_me"))
        metadata = dict(options.get("metadata") or {})
        if remember_me:
            metadata[REMEMBER_ME_META_KEY] = True
        session_id, csrf = await self.manager.create_session(
            request,
            user_id=runtime.repo.user_id(user),
            metadata=metadata,
            token_version=runtime.repo.token_version(user),
        )
        cookie_max_age = self.manager.timeout_seconds_for(metadata) if remember_me else None
        self.manager.set_session_cookies(response, session_id, csrf, max_age=cookie_max_age)
        await runtime.hooks.run_after_login(
            runtime.repo.to_dict(user),
            request=request,
            context=HookContext(
                ip_address=get_client_ip(request, runtime.trusted_proxy_hops),
                user_agent=request.headers.get("user-agent"),
                transport=metadata.get("login_type", self.name),
                request=request,
                session_handle=self.manager.session_handle(session_id),
            ),
        )
        return {
            "id": runtime.repo.user_id(user),
            "username": runtime.repo.get(user, "username"),
            "csrf_token": csrf,
        }

    async def complete_logout(self, request: Request, response: Response, db: Any) -> bool:
        """End the session the request's cookie names, clear the cookies, and fire ``on_after_logout``.

        What ``/logout`` does, for an app with a logout route of its own (an HTML form,
        say). A live session must pass the CSRF check first, so the request needs the
        ``X-CSRF-Token`` header; one that already expired has nothing left to protect,
        so its cookies are cleared without it. Every configured transport's cookies are
        cleared, a bearer refresh cookie included. The hook gets the account and a
        context naming the session that ended by its ``session_handle``.

        Returns:
            ``True`` if a session was ended, ``False`` if there was none to end.

        Raises:
            CSRFException: A live session without a valid CSRF token.

        Example:
            ```python
            @app.post("/admin/logout")
            async def admin_logout(request: Request, db=Depends(get_db)):
                response = RedirectResponse("/admin/login", status_code=303)
                await session_transport.complete_logout(request, response, db)
                return response
            ```
        """
        assert self.manager is not None
        runtime = self.runtime
        session_id = request.cookies.get(self.manager.session_cookie_name)
        session = (
            await self.manager.validate_session(session_id, update_activity=False)
            if session_id
            else None
        )
        user_dict = None
        ended = False
        if session_id and session is not None:
            await self.enforce_csrf(request, session_id)
            user = await runtime.repo.get_by_id(db, session.user_id)
            if user is not None:
                user_dict = runtime.repo.to_dict(user)
            ended = await self.manager.terminate_session(session_id, reason="logout")
        runtime.clear_cookies(response)
        if user_dict is not None and session_id:
            await runtime.hooks.run_after_logout(
                user_dict,
                request=request,
                context=HookContext(
                    ip_address=get_client_ip(request, runtime.trusted_proxy_hops),
                    user_agent=request.headers.get("user-agent"),
                    transport=self.name,
                    request=request,
                    session_handle=self.manager.session_handle(session_id),
                ),
            )
        return ended

    def clear_cookies(self, response: Response) -> None:
        """Expire the session and CSRF cookies."""
        assert self.manager is not None
        self.manager.clear_session_cookies(response)

    # --- routes --------------------------------------------------------------
    def contributes_routes(self) -> APIRouter:
        return build_session_routes(self)
