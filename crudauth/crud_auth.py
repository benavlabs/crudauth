"""``CRUDAuth`` - the one object you configure and mount.

```python
auth = CRUDAuth(session=get_session, user_model=User, SECRET_KEY="...")
app.include_router(auth.router)

@app.get("/me")
async def me(user: Principal = Depends(auth.current_user())):
    return {"id": user.user_id}
```
"""

import inspect
import logging
from typing import TYPE_CHECKING, Annotated, Any, Callable, Sequence

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field

from .register import build_register_route
from .constants import (
    DEFAULT_ALGORITHM,
    DEFAULT_LOGIN_ATTEMPT_WINDOW_SECONDS,
    DEFAULT_LOGIN_LOCKOUT_BASE_SECONDS,
    DEFAULT_LOGIN_LOCKOUT_MAX_SECONDS,
    DEFAULT_LOGIN_MAX_ATTEMPTS,
    MIN_PASSWORD_LENGTH,
    OAUTH_STATE_TTL_SECONDS,
    USED_TOKEN_TTL_SECONDS,
)
from .core import AuthContext, AuthRuntime, CookieConfig, Transport
from .email.channel import DeliveryChannel
from .email.router import build_email_router
from .email.service import EmailFlowService
from .exceptions import (
    BadRequestException,
    ForbiddenException,
    RateLimitException,
    UnauthorizedException,
)
from .hooks import AuthHooks
from .identity import IdentityConfig
from .oauth import OAuthAccountService, OAuthProviderFactory
from .oauth.router import build_oauth_router
from .principal import Principal
from .provisioning import NewUserFields
from .ratelimit import (
    DEFAULT_RATE_LIMITS,
    KeyBy,
    LockoutPolicy,
    MemoryRateLimiterBackend,
    RateLimit,
)
from .ratelimit.constants import RATE_LIMIT_NAMESPACE
from .repository import REGISTRATION_ALLOWED_FIELDS, UserRepository
from .storage import get_session_storage
from .sudo import SudoConfig, SudoManager
from .storage.constants import BACKEND_MEMORY
from .transports.bearer.transport import BearerTransport
from .transports.session.transport import SessionTransport
from .utils import get_client_ip, get_password_hash, is_unusable_password

if TYPE_CHECKING:  # pragma: no cover
    from .ratelimit import RateLimiterBackend
    from .storage.base import AbstractSessionStorage

logger = logging.getLogger("crudauth")

__all__ = ["CRUDAuth"]


class _SetPasswordIn(BaseModel):
    new_password: Annotated[str, Field(min_length=MIN_PASSWORD_LENGTH)]


class CRUDAuth:
    """Composition root: configure transports, mount routers, gate routes.

    Construct one per auth surface. It owns the user repository, the shared
    [AuthRuntime][crudauth.core.AuthRuntime], the rate-limiter backend, and the
    assembled routers. Session auth is the default; add bearer/oauth/email by
    passing ``transports=``, ``oauth=``, ``email=``.

    Example:
        ```python
        auth = CRUDAuth(session=get_session, user_model=User, SECRET_KEY="change-me")
        app.include_router(auth.router)

        @app.get("/me")
        async def me(user: Principal = Depends(auth.current_user())):
            return {"id": user.user_id}
        ```
    """

    def __init__(
        self,
        *,
        session: Callable[..., Any],
        user_model: type[Any],
        SECRET_KEY: str,
        transports: Sequence[Transport] | None = None,
        column_map: dict[str, str] | None = None,
        identity: IdentityConfig | None = None,
        oauth: dict[str, Any] | None = None,
        email: Any = None,
        channels: list[DeliveryChannel] | None = None,
        hooks: AuthHooks | None = None,
        redirect_base_url: str | None = None,
        algorithm: str = DEFAULT_ALGORITHM,
        cookies: CookieConfig | None = None,
        register_schema: type[BaseModel] | None = None,
        register_extra_fields: set[str] | None = None,
        new_user_fields: NewUserFields | None = None,
        new_user_defaults: dict[str, Any] | None = None,
        rate_limiter: "RateLimiterBackend | None" = None,
        rate_limits: dict[str, RateLimit] | None = None,
        trusted_proxy_hops: int = 0,
        sudo: SudoConfig | None = None,
        warn_on_memory_backend: bool = True,
    ):
        """Configure the auth surface.

        Args:
            session: FastAPI dependency that yields an ``AsyncSession`` (your
                ``get_session``); every route and the ``current_user`` dependency
                acquire the DB through it.
            user_model: Your SQLAlchemy user model (typically inheriting
                [AuthUserMixin][crudauth.models.mixin.AuthUserMixin]).
            SECRET_KEY: Secret used to sign session/JWT and email tokens.
            transports: Ordered auth channels to enable; defaults to a single
                [SessionTransport][crudauth.transports.session.transport.SessionTransport]. Order is the first-wins precedence.
            column_map: Maps crudauth logical field names to your model's actual
                column names when they differ (e.g. ``{"hashed_password": "pw_hash"}``).
            oauth: ``{provider_name: OAuthCredentials}`` to enable OAuth login;
                requires ``redirect_base_url`` and a session transport.
            email: An [EmailConfig][crudauth.email.config.EmailConfig] to enable
                verify/reset/change flows over email (the built-in delivery
                channel); ``None`` disables email delivery. Either ``email`` or
                ``channels`` enables the recovery endpoints.
            channels: Additional [DeliveryChannel][crudauth.email.channel.DeliveryChannel]s
                to route recovery tokens over (SMS, WhatsApp, push, ...). Fired
                alongside the email channel if ``email`` is also set, every channel
                best-effort. With ``channels`` and no ``email``, the recovery
                endpoints still mount (token lifetimes fall back to the defaults).
            hooks: Lifecycle callbacks ([AuthHooks][crudauth.hooks.AuthHooks]).
            redirect_base_url: Public base URL used to build OAuth redirect URIs
                and the post-login redirect default.
            algorithm: JWT signing algorithm (default ``"HS256"``).
            cookies: App-wide [CookieConfig][crudauth.core.CookieConfig] (``secure`` /
                ``samesite`` / ``path``); transports may override per-instance.
            register_schema: Custom Pydantic body for ``/register``. By default
                only ``email``/``username`` are persisted; any other field is
                dropped unless its name is listed in ``register_extra_fields``.
            register_extra_fields: App-defined model columns that ``/register``
                is allowed to set (e.g. ``{"full_name", "locale"}``). Registration
                is an allowlist: without opting a column in here it is dropped,
                so adding a column to your model never silently becomes settable
                at signup. crudauth's privileged fields (``is_superuser``,
                ``email_verified``, ...) can never be opted in.
            new_user_defaults: Constant app columns to set on every new user, on
                BOTH ``/register`` and OAuth signup (e.g. ``{"tier_id": FREE}``).
                The declarative shortcut for fixed values; gated like
                ``new_user_fields`` (a crudauth-owned key is dropped + warned at
                construction).
            new_user_fields: Callback (sync or async) returning extra columns to
                set when crudauth creates a user, for values that must be
                *derived* (and may read the DB) rather than constant - e.g.
                ``lambda ctx: {"name": ctx.suggested_name}``. Receives a trusted
                [NewUserContext][crudauth.provisioning.NewUserContext] (never the
                request body) and returns app columns only, as a ``dict`` or a
                ``BaseModel``; any crudauth logical field it returns is dropped
                (crudauth stays authoritative). Merged into the single insert
                after ``new_user_defaults``, so a derived value can override a
                constant default. Client-typed fields belong in ``register_schema``
                /``register_extra_fields``, not here.
            rate_limiter: Backend for lockout/throttles; defaults to an in-process
                [MemoryRateLimiterBackend][crudauth.ratelimit.backends.memory.MemoryRateLimiterBackend]. Use
                ``redis_rate_limiter(...)`` in production.
            rate_limits: Per-action overrides merged over
                :data:`~crudauth.ratelimit.DEFAULT_RATE_LIMITS`.
            trusted_proxy_hops: Number of trusted reverse proxies in front of the
                app. ``0`` (default) ignores ``X-Forwarded-For`` and keys per-IP
                rate limits / lockout on the socket peer; set to the count of
                proxies you control (e.g. ``1`` behind a single nginx/Caddy) so
                the real client IP is read without trusting attacker-supplied
                header values. See [get_client_ip][crudauth.utils.get_client_ip].
            sudo: Enable sudo mode (short-lived re-authentication for sensitive
                actions) with this [SudoConfig][crudauth.sudo.SudoConfig]. Requires
                a session transport - elevation is stamped on the server-side
                session. Exposes ``auth.sudo`` and ``auth.require_sudo()``.
            warn_on_memory_backend: Log a startup warning when an in-memory
                backend is active (the zero-config default). In-memory state is
                per-process, so under multiple workers it silently breaks; set
                ``False`` to silence once you've accepted that (e.g. single-worker
                dev).

        Raises:
            ValueError: If ``SECRET_KEY`` is empty; if ``oauth`` or ``sudo`` is
                set without a session transport (and ``oauth`` also needs
                ``redirect_base_url``); or if a configured OAuth provider has no
                ``{provider}_id`` column on the user model.
        """
        if not SECRET_KEY:
            raise ValueError("SECRET_KEY is required")
        self.session = session
        self.identity = identity or IdentityConfig()
        self.repo = UserRepository(
            user_model, column_map, register_extra_fields, login_fields=self.identity.login
        )
        self._validate_identity(oauth=oauth, email=email)
        self.new_user_fields = new_user_fields
        self._new_user_defaults = self.repo.filter_provisioning_data(new_user_defaults or {})
        self.hooks = hooks or AuthHooks()
        self.transports: list[Transport] = list(transports) if transports else [SessionTransport()]
        self._register_schema = register_schema
        self._warn_on_register_extra_fields(register_extra_fields)
        self._warn_on_privileged_register_fields(register_schema)
        self._rate_limits: dict[str, RateLimit] = {**DEFAULT_RATE_LIMITS, **(rate_limits or {})}

        self.runtime = AuthRuntime(
            secret_key=SECRET_KEY,
            repo=self.repo,
            hooks=self.hooks,
            redirect_base_url=redirect_base_url,
            db_dependency=session,
            algorithm=algorithm,
            cookie_config=cookies or CookieConfig(),
            rate_limiter=rate_limiter or MemoryRateLimiterBackend(),
            trusted_proxy_hops=trusted_proxy_hops,
        )
        self._session_transport = next(
            (t for t in self.transports if isinstance(t, SessionTransport)), None
        )
        self.runtime.lockout = self._build_lockout(self._session_transport)
        for transport in self.transports:
            transport.bind(self.runtime)

        self.sudo: SudoManager | None = None
        if sudo is not None:
            self._build_sudo(sudo)

        self._email_service: EmailFlowService | None = None
        self._email_token_store: AbstractSessionStorage[Any] | None = None
        if self.identity.recovery is not None and (email is not None or channels):
            self._build_email(email, channels, algorithm)

        self._oauth_router: APIRouter | None = None
        self._oauth_state_storage: AbstractSessionStorage[Any] | None = None
        if oauth:
            self._build_oauth(oauth, redirect_base_url)

        if warn_on_memory_backend:
            self._warn_on_memory_backend()

    def _build_lockout(
        self, session_transport: "SessionTransport | None"
    ) -> "LockoutPolicy | None":
        """Build the one shared login-lockout policy (or ``None`` if no limiter).

        Note:
            Called before transports are bound, because both the session and
            bearer transports read ``runtime.lockout`` in their ``bind``/routes.
            Mirrors the session transport's lockout config when present, else
            uses defaults - so a bearer-only API still gets lockout.
        """
        if self.runtime.rate_limiter is None:
            return None
        st = session_transport
        return LockoutPolicy(
            self.runtime.rate_limiter,
            max_attempts=st.login_max_attempts if st else DEFAULT_LOGIN_MAX_ATTEMPTS,
            attempt_window_seconds=(
                st.login_attempt_window_seconds if st else DEFAULT_LOGIN_ATTEMPT_WINDOW_SECONDS
            ),
            lockout_base_seconds=(
                st.login_lockout_base_seconds if st else DEFAULT_LOGIN_LOCKOUT_BASE_SECONDS
            ),
            lockout_max_seconds=(
                st.login_lockout_max_seconds if st else DEFAULT_LOGIN_LOCKOUT_MAX_SECONDS
            ),
            on_login_success=st.on_login_success if st else "clear_all",
            fail_open=False,
        )

    def _validate_identity(self, *, oauth: dict[str, Any] | None, email: Any) -> None:
        """Check the identity contract against the model, fail-closed at construction.

        The model owns the shape; this asserts the config agrees with it, so a
        login field that isn't a unique column, a non-unique recovery field, OAuth
        without an email login, or an email flow on a model with no email column
        all raise here rather than splitting into a silent second source of truth.
        """
        for login_field in self.identity.login:
            if not self.repo.is_unique_column(login_field):
                raise ValueError(
                    f"identity.login field '{login_field}' is not a unique column on the user "
                    "model; every login field must be a single-field unique column."
                )
        recovery = self.identity.recovery
        if recovery is not None and not self.repo.is_unique_column(recovery):
            raise ValueError(
                f"identity.recovery field '{recovery}' is not a unique column on the user "
                "model; the recovery field must be a single-field unique column."
            )
        if oauth and "email" not in self.identity.login:
            raise ValueError(
                "OAuth requires 'email' in identity.login - OAuth links and creates accounts "
                "by email, so an email-less contract cannot enable OAuth."
            )
        if email is not None and not self.repo.has("email"):
            raise ValueError("email=EmailConfig(...) requires an 'email' column on the user model.")

    def _warn_on_register_extra_fields(self, extra: set[str] | None) -> None:
        """Warn when ``register_extra_fields`` tries to opt in a privileged field.

        Those names stay gated regardless (the repo drops them), so this is a
        no-op for safety - but it's a developer misconfiguration worth surfacing.
        """
        if not extra:
            return
        gated = self.repo.gated_register_fields(extra)
        if gated:
            logger.warning(
                "register_extra_fields lists privileged field(s) %s; these stay gated "
                "and will NOT be settable at registration. Remove them.",
                sorted(gated),
            )

    def _warn_on_privileged_register_fields(self, schema: type[BaseModel] | None) -> None:
        """Warn when a custom register schema declares fields registration drops.

        Two cases, both surfaced at startup so a silent drop never bites:

        - **Privileged** fields (``is_superuser``, ``email_verified``, ...) are
          dropped unconditionally - declaring one is a security-relevant mistake.
        - **Real model columns** that aren't opted in via ``register_extra_fields``
          are also dropped; the developer likely expected them to persist.
        """
        if schema is None:
            return
        fields = schema.model_fields.keys()
        gated = self.repo.gated_register_fields(fields)
        if gated:
            logger.warning(
                "register_schema %s declares privileged field(s) %s that registration "
                "will ignore. /register may only set %s plus columns you opt in via "
                "register_extra_fields; remove these from the schema.",
                schema.__name__,
                sorted(gated),
                sorted(REGISTRATION_ALLOWED_FIELDS),
            )
        droppable = self.repo.droppable_register_fields(fields)
        if droppable:
            logger.warning(
                "register_schema %s declares field(s) %s that map to model columns but "
                "are not opted in; registration will drop them. Add them to "
                "register_extra_fields=%s to persist them.",
                schema.__name__,
                sorted(droppable),
                sorted(droppable),
            )

    # --- backend detection ---------------------------------------------------
    def _backend_config(self) -> tuple[str, str | None]:
        if self._session_transport is not None:
            return self._session_transport.backend, self._session_transport.redis_url
        return BACKEND_MEMORY, None

    def _warn_on_memory_backend(self) -> None:
        """Warn when an in-memory backend is active (the zero-config default).

        In-memory state is per-process: under multiple workers it is not shared,
        so login-lockout counters, sessions/CSRF tokens, and single-use token /
        OAuth-state atomicity silently weaken. Production should use redis.
        """
        memory: list[str] = []
        if isinstance(self.runtime.rate_limiter, MemoryRateLimiterBackend):
            memory.append("rate limiter (lockout/throttle counters)")
        if self._backend_config()[0] == BACKEND_MEMORY:
            memory.append("sessions/CSRF and one-time-token/OAuth-state stores")
        if not memory:
            return
        logger.warning(
            "crudauth: using in-memory backend(s) - %s. In-memory state is per-process, so "
            "under multiple workers it is NOT shared: lockout counters, sessions/CSRF, and "
            "single-use token/OAuth-state atomicity weaken silently. Use redis in production "
            "(redis_rate_limiter(...) and SessionTransport(backend='redis')), or pass "
            "warn_on_memory_backend=False to silence.",
            " and ".join(memory),
        )

    # --- public: session manager --------------------------------------------
    @property
    def sessions(self):
        """The [SessionManager][crudauth.transports.session.manager.SessionManager] of the configured session transport."""
        if self._session_transport is None or self._session_transport.manager is None:
            raise RuntimeError(
                "Session management requires a SessionTransport in transports=[...]."
            )
        return self._session_transport.manager

    # --- email wiring --------------------------------------------------------
    def _build_email(
        self, email: Any, channels: list[DeliveryChannel] | None, algorithm: str
    ) -> None:
        backend, redis_url = self._backend_config()
        token_store = get_session_storage(
            backend, prefix="used_token:", expiration=USED_TOKEN_TTL_SECONDS, redis_url=redis_url
        )
        self._email_token_store = token_store
        self._email_service = EmailFlowService(
            repo=self.repo,
            secret_key=self.runtime.secret_key,
            config=email,
            channels=channels,
            hooks=self.hooks,
            algorithm=algorithm,
            token_store=token_store,
            session_manager=self.sessions if self._session_transport else None,
            rate_limiter=self.runtime.rate_limiter,
            rate_limits=self._rate_limits,
        )
        self.runtime.email_service = self._email_service

    # --- oauth wiring --------------------------------------------------------
    def _build_oauth(self, oauth: dict[str, Any], redirect_base_url: str | None) -> None:
        if self._session_transport is None:
            raise ValueError(
                "OAuth establishes a session on callback; add a SessionTransport to transports=[...]."
            )
        if not redirect_base_url:
            raise ValueError("redirect_base_url is required when oauth=... is configured")

        providers = {}
        for name, creds in oauth.items():
            if not self.repo.has(f"{name}_id"):
                raise ValueError(
                    f"OAuth provider {name!r} needs a '{name}_id' column on the user model "
                    f"to store and match its account id. Add it (e.g. "
                    f"'{name}_id: Mapped[str | None] = mapped_column(unique=True, index=True, "
                    f"default=None)') or map it via column_map=."
                )
            redirect_uri = f"{redirect_base_url.rstrip('/')}/oauth/{name}/callback"
            providers[name] = OAuthProviderFactory.create_provider(
                name,
                client_id=creds.client_id,
                client_secret=creds.client_secret,
                redirect_uri=redirect_uri,
                scopes=creds.scopes,
            )

        backend, redis_url = self._backend_config()
        state_storage = get_session_storage(
            backend, prefix="oauth_state:", expiration=OAUTH_STATE_TTL_SECONDS, redis_url=redis_url
        )
        self._oauth_state_storage = state_storage
        self._oauth_router = build_oauth_router(
            runtime=self.runtime,
            providers=providers,
            state_storage=state_storage,
            account_service=OAuthAccountService(
                self.repo, self.new_user_fields, self._new_user_defaults
            ),
            session_manager=self.sessions,
            default_redirect=redirect_base_url,
        )

    # --- sudo wiring ---------------------------------------------------------
    def _build_sudo(self, config: SudoConfig) -> None:
        if self._session_transport is None:
            raise ValueError(
                "Sudo stamps the elevation on a server-side session; add a "
                "SessionTransport to transports=[...]."
            )
        self.sudo = SudoManager(
            session_manager=self.sessions,
            repo=self.repo,
            backend=self.runtime.rate_limiter,
            hooks=self.hooks,
            config=config,
        )

    # --- the current_user() factory -----------------------------------------
    async def _resolve_principal(
        self, request: Request, db: Any, selected: list[Transport]
    ) -> Principal | None:
        """Run the transport loop once per request, per transport selection.

        Cached on ``request.state`` so multiple gates over the same selection in
        one request (e.g. ``current_user()`` plus a ``KeyBy.USER`` rate limit,
        which calls ``current_user()`` internally) share a single authentication
        - one transport loop, one user load, one CSRF check - instead of running
        it once per dependency. Gates (superuser/scopes/check) are still applied
        per call by the caller, on the shared principal.
        """
        cache = getattr(request.state, "_crudauth_principals", None)
        if cache is None:
            cache = {}
            request.state._crudauth_principals = cache
        key = tuple(t.name for t in selected)
        if key in cache:
            return cache[key]
        ctx = AuthContext(request=request, db=db, runtime=self.runtime)
        principal: Principal | None = None
        for t in selected:
            principal = await t.authenticate(request, ctx)
            if principal is not None:
                break
        cache[key] = principal
        return principal

    def current_user(
        self,
        *,
        optional: bool = False,
        superuser: bool = False,
        verified: bool = False,
        scopes: list[str] | None = None,
        transport: str | list[str] | None = None,
        check: Callable[[Principal], Any] | None = None,
    ) -> Callable[..., Any]:
        """Build a FastAPI dependency that authenticates and authorizes a request.

        Every gate is a keyword: ``optional``, ``superuser``, ``verified``,
        ``scopes``, ``transport`` (narrow to one/some transports), and ``check``.

        Note:
            ``check`` is a predicate (sync or async) run last on the resolved
            principal. Returning ``False`` denies the request with 403. To deny
            with a custom status/message, raise your own exception from inside
            ``check``. Returning ``None`` (or anything that isn't ``False``)
            allows - so both styles work: a boolean predicate
            (``check=lambda p: p.is_superuser``) and a raise-to-deny callback that
            simply returns nothing on success.

        Note:
            Transports are tried in order, first credential wins. A transport
            returns ``None`` when its credential is *absent* (move to the next),
            but RAISES for a *present-but-invalid* one (e.g. a session cookie that
            fails the CSRF header check on a mutation). That hard-fail propagates
            even under ``optional=True`` - a tampered credential is an attack
            signal, not "treat me as anonymous".

        Returns:
            An async dependency yielding the [Principal][crudauth.principal.Principal] (or ``None`` when
            ``optional`` and no credential is present).

        Example:
            ```python
            @app.get("/admin")
            async def admin(_: Principal = Depends(auth.current_user(superuser=True))):
                ...
            ```
        """
        if verified and not self.repo.has("email"):
            raise ValueError(
                "current_user(verified=True) gates on email_verified, which requires an "
                "email column on the user model. (PR-1 placeholder; recovery_verified is PR 2.)"
            )
        selected = self._select_transports(transport)
        required_scopes = list(scopes or [])

        async def dependency(
            request: Request, db: Annotated[Any, Depends(self.session)]
        ) -> Principal | None:
            principal = await self._resolve_principal(request, db, selected)

            if principal is None:
                if optional:
                    return None
                raise UnauthorizedException("Not authenticated")

            if superuser and not principal.is_superuser:
                raise ForbiddenException("Insufficient privileges")
            if verified and not principal.email_verified:
                raise ForbiddenException("Email not verified")
            if required_scopes and not principal.has_scopes(required_scopes):
                raise ForbiddenException("Insufficient scope")
            if check is not None:
                result = check(principal)
                if inspect.isawaitable(result):
                    result = await result
                if result is False:
                    raise ForbiddenException("Access denied")
            return principal

        return dependency

    def require_sudo(self) -> Callable[..., Any]:
        """Build a dependency that requires a current sudo elevation.

        Authenticates like [current_user][crudauth.crud_auth.CRUDAuth.current_user]
        (reusing the per-request principal cache) and then demands an unexpired
        sudo stamp, raising 403 otherwise. Compose it with ``current_user`` gates
        on the same route to also enforce identity/role:

        Example:
            ```python
            @app.post("/account/close")
            async def close(
                user: Principal = Depends(auth.current_user(superuser=True)),
                _: Principal = Depends(auth.require_sudo()),
            ):
                ...
            ```

        Raises:
            RuntimeError: If sudo isn't configured (pass ``sudo=SudoConfig()``).
        """
        if self.sudo is None:
            raise RuntimeError("Sudo is not configured; pass sudo=SudoConfig() to CRUDAuth.")
        sudo = self.sudo
        user_dep = self.current_user()

        async def dependency(principal: Annotated[Principal, Depends(user_dep)]) -> Principal:
            if not await sudo.is_elevated(principal):
                raise ForbiddenException("Re-authentication required.")
            return principal

        return dependency

    def _select_transports(self, transport: str | list[str] | None) -> list[Transport]:
        if transport is None:
            return self.transports
        names = [transport] if isinstance(transport, str) else list(transport)
        selected = [t for t in self.transports if t.name in names]
        if not selected:
            raise ValueError(
                f"No configured transport matches {names!r}; "
                f"configured: {[t.name for t in self.transports]}"
            )
        return selected

    # --- the rate_limit() factory -------------------------------------------
    def rate_limit(
        self,
        action: str,
        limit: RateLimit | None = None,
        *,
        key: "KeyBy | Callable[[Request], str]" = KeyBy.IP,
    ) -> Callable[..., Any]:
        """Build a FastAPI dependency that throttles an endpoint.

        Resolves the limit (explicit ``limit`` → ``rate_limits=`` override →
        :data:`~crudauth.ratelimit.DEFAULT_RATE_LIMITS`), keys by IP, user, or a
        custom function, writes ``X-RateLimit-*`` headers, and raises
        [RateLimitException][crudauth.exceptions.RateLimitException] (429) when the caller exceeds the window.

        Example:
            ```python
            @app.post("/contact", dependencies=[Depends(auth.rate_limit("contact", RateLimit(5, 60)))])
            async def contact(...): ...
            ```
        """
        resolved = limit or self._rate_limits.get(action) or DEFAULT_RATE_LIMITS.get(action)
        if resolved is None:
            raise ValueError(
                f"No rate limit configured for action {action!r}; pass limit=RateLimit(...)."
            )

        if key is KeyBy.USER:
            user_dep = self.current_user()

            async def by_user(
                response: Response, principal: Annotated[Principal, Depends(user_dep)]
            ) -> None:
                await self._apply_rate_limit(response, action, str(principal.user_id), resolved)

            return by_user

        if key is KeyBy.IP:

            async def by_ip(request: Request, response: Response) -> None:
                ip = get_client_ip(request, self.runtime.trusted_proxy_hops)
                await self._apply_rate_limit(response, action, ip, resolved)

            return by_ip

        keyfn = key

        async def by_custom(request: Request, response: Response) -> None:
            await self._apply_rate_limit(response, action, keyfn(request), resolved)

        return by_custom

    async def _apply_rate_limit(
        self, response: Response, action: str, ident: str, limit: RateLimit
    ) -> None:
        """Run the window check, set ``X-RateLimit-*`` headers, raise 429 if over.

        Note:
            Headers set on the injected ``Response`` are dropped when the
            dependency raises, so the limit headers are also attached to the
            ``RateLimitException`` on the over-limit path.
        """
        backend = self.runtime.rate_limiter
        if backend is None or limit.disabled:
            return
        count, limited, retry_after = await backend.increment_and_check(
            f"{RATE_LIMIT_NAMESPACE}:{action}:{ident}", limit.times, limit.seconds, fail_open=True
        )
        response.headers["X-RateLimit-Limit"] = str(limit.times)
        response.headers["X-RateLimit-Remaining"] = str(max(0, limit.times - count))
        if limited:
            raise RateLimitException(
                "Too many requests. Try again later.",
                retry_after=retry_after,
                headers={
                    "X-RateLimit-Limit": str(limit.times),
                    "X-RateLimit-Remaining": "0",
                },
            )

    # --- shared routes -------------------------------------------------------
    def _shared_router(self) -> APIRouter:
        router = APIRouter(tags=["auth"])
        router.include_router(build_register_route(self, self._register_schema))

        @router.get("/me")
        async def me(user: Annotated[Principal, Depends(self.current_user())]):
            """Return the authenticated user's identity, scopes, and auth transport."""
            return {
                "user_id": user.user_id,
                "username": self.repo.get(user.user, "username") if user.user else None,
                "email": self.repo.get(user.user, "email") if user.user else None,
                "is_superuser": user.is_superuser,
                "scopes": list(user.scopes),
                "via": user.transport,
            }

        @router.post("/set-password")
        async def set_password(
            body: _SetPasswordIn,
            principal: Annotated[Principal, Depends(self.current_user())],
            db: Annotated[Any, Depends(self.session)],
        ):
            """Set a password for an account that doesn't have one (OAuth-only).

            Note:
                The active session/credential IS the re-authentication - there's
                no current password to check because the account never had one.
                This is **set**, not **change**: it refuses (400) if the account
                already has a usable password (use the password-reset flow to
                change an existing one). It does not evict other sessions/tokens
                (establishing a first credential isn't a compromise response).

            Note:
                Allowed over any transport. On the session path the POST already
                carries CSRF; on the bearer path there's no CSRF surface (the
                token is sent explicitly, not auto-attached), and a valid bearer
                token is itself proof of the active credential - the same re-auth
                argument. Narrow with ``transport="session"`` if your policy
                requires first-password establishment to be browser-only.
            """
            user = principal.user
            if not is_unusable_password(self.repo.get(user, "hashed_password", "")):
                raise BadRequestException(
                    "Account already has a password; use the password reset flow to change it."
                )
            await self.repo.update(
                db, user, {"hashed_password": get_password_hash(body.new_password)}
            )
            return {"detail": "Password set."}

        return router

    # --- assembled routers ---------------------------------------------------
    @property
    def router(self) -> APIRouter:
        """The full router to mount: shared (``/register``, ``/me``) plus every
        transport's routes, plus OAuth and email routes when configured.

        Returns:
            An `APIRouter` to pass to ``app.include_router``.

        Example:
            ```python
            app.include_router(auth.router)
            ```
        """
        router = APIRouter()
        router.include_router(self._shared_router())
        for t in self.transports:
            sub = t.contributes_routes()
            if sub is not None:
                router.include_router(sub)
        if self._oauth_router is not None:
            router.include_router(self._oauth_router)
        if self._email_service is not None:
            router.include_router(build_email_router(auth=self, service=self._email_service))
        return router

    @property
    def session_router(self) -> APIRouter:
        """Only the session transport's routes (``/login``, ``/logout``).

        Raises:
            RuntimeError: If no [SessionTransport][crudauth.transports.session.transport.SessionTransport] is configured.
        """
        if self._session_transport is None:
            raise RuntimeError("No SessionTransport configured")
        return self._session_transport.contributes_routes()

    @property
    def bearer_router(self) -> APIRouter:
        """Only the bearer transport's routes (``/token``, ``/refresh``).

        Raises:
            RuntimeError: If no [BearerTransport][crudauth.transports.bearer.transport.BearerTransport] is configured.
        """
        bearer = next((t for t in self.transports if isinstance(t, BearerTransport)), None)
        if bearer is None:
            raise RuntimeError("No BearerTransport configured")
        return bearer.contributes_routes()

    # --- lifecycle -----------------------------------------------------------
    async def initialize(self) -> None:
        """Open storage/limiter connections; call from your app's lifespan startup.

        Idempotent per component. Required for server-side backends (redis); a
        no-op for the in-memory defaults.

        Example:
            ```python
            @asynccontextmanager
            async def lifespan(app):
                await auth.initialize()
                yield
                await auth.shutdown()
            ```
        """
        if self.runtime.rate_limiter is not None:
            await self.runtime.rate_limiter.initialize()
        for t in self.transports:
            await t.initialize()
        if self._oauth_state_storage is not None:
            await self._oauth_state_storage.initialize()
        if self._email_token_store is not None:
            await self._email_token_store.initialize()

    async def shutdown(self) -> None:
        """Close connections. Call in lifespan teardown."""
        for t in self.transports:
            await t.shutdown()
        if self._oauth_state_storage is not None:
            await self._oauth_state_storage.close()
        if self._email_token_store is not None:
            await self._email_token_store.close()
        if self.runtime.rate_limiter is not None:
            await self.runtime.rate_limiter.close()
