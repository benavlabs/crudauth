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
from dataclasses import asdict
from types import MappingProxyType
from typing import (
    TYPE_CHECKING,
    Annotated,
    Any,
    Awaitable,
    Callable,
    Literal,
    Mapping,
    Sequence,
    TypeVar,
)

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from .account import build_account_router
from .constants import DEFAULT_ALGORITHM, OAUTH_STATE_TTL_SECONDS, USED_TOKEN_TTL_SECONDS
from .core import AuthRuntime, CookieConfig, Transport
from .email.channel import DeliveryChannel
from .email.router import build_email_router
from .email.service import EmailFlowService
from .exceptions import ForbiddenException, UnauthorizedException
from .hooks import AuthHooks
from .identity import IdentityConfig
from .mfa import MfaConfig, MfaService
from .mfa.constants import CHALLENGE_STORAGE_PREFIX, MFA_FIELDS
from .mfa.router import build_mfa_router
from .oauth import (
    AbstractOAuthProvider,
    GenericOIDCProvider,
    OAuthAccountService,
    OAuthCredentials,
    OAuthProviderFactory,
)
from .oauth.paths import callback_url, is_redirect_target, resolve_oauth_paths
from .oauth.router import build_oauth_router
from .password import PasswordContext, PasswordPolicy, PasswordSource
from .principal import Principal
from .provisioning import NewUserFields
from .ratelimit import (
    DEFAULT_RATE_LIMITS,
    KeyBy,
    LockoutConfig,
    LockoutPolicy,
    MemoryRateLimiterBackend,
    RateLimit,
    RateLimitResolver,
    redis_rate_limiter,
)
from .ratelimit.dependency import limit_by_request, limit_by_user
from .register import build_register_route
from .repository import REGISTRATION_ALLOWED_FIELDS, UserRepository
from .resolution import PrincipalResolver
from .storage import DatabaseStore, MemorySessionStorage, get_session_storage
from .storage.backends.redis import redis_client_from_url
from .storage.constants import BACKEND_CUSTOM, BACKEND_DATABASE, BACKEND_MEMORY, BACKEND_REDIS
from .sudo import SudoConfig, SudoManager
from .transports.bearer.transport import BearerTransport
from .transports.session.management import build_session_management_router
from .transports.session.manager import SessionManager
from .transports.session.transport import SessionTransport
from .utils import LegacyVerifier

if TYPE_CHECKING:  # pragma: no cover
    from .ratelimit import RateLimiterBackend
    from .storage.base import AbstractSessionStorage

logger = logging.getLogger("crudauth")

__all__ = ["CRUDAuth"]

TransportT = TypeVar("TransportT", bound=Transport)

MEMORY_TOKEN_STORES = "one-time-token/OAuth-state stores"
MEMORY_MFA_STORE = "MFA store"


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
        oauth_paths: dict[str, str] | None = None,
        oauth_response_mode: Literal["redirect", "json"] = "redirect",
        oauth_default_redirect: str | None = None,
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
        redis_url: str | None = None,
        redis_client: Any = None,
        database_store: DatabaseStore | None = None,
        rate_limit_prefix: str | None = None,
        rate_limits: dict[str, RateLimit] | None = None,
        lockout: LockoutConfig | None = None,
        trusted_proxy_hops: int = 0,
        sudo: SudoConfig | None = None,
        mfa: MfaConfig | None = None,
        warn_on_memory_backend: bool = True,
        password_policy: PasswordPolicy | None = None,
        legacy_verifiers: Sequence[LegacyVerifier] | None = None,
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
            oauth_paths: Optional OAuth router paths: ``prefix``,
                ``authorize_path``, and ``callback_path``. Defaults to
                ``{"prefix": "/oauth", "authorize_path": "/{provider}/authorize",
                "callback_path": "/{provider}/callback"}``. Both paths must contain
                ``{provider}``. The provider redirect URI is ``redirect_base_url``
                plus ``prefix`` plus the callback path, so ``redirect_base_url``
                must include any prefix the app adds when mounting the router.
            oauth_response_mode: ``"redirect"`` (default) or ``"json"``. In JSON
                mode ``authorize`` returns ``{"url": ...}`` and ``callback``
                returns ``{"user": ..., "csrf_token": ..., "redirect_to": ...}``
                with the session cookies set, or a ``400`` on failure.
            oauth_default_redirect: Where a redirect-mode callback sends the browser
                when ``redirect_to`` is absent or unsafe, on failure (with
                ``?error=<code>``) and on an MFA challenge (with
                ``#mfa_challenge=...``). A same-origin path such as ``"/app/login"``
                or an absolute ``http(s)`` URL; defaults to ``redirect_base_url``.
                Set it when the app doesn't live at the root of
                ``redirect_base_url``, which can't carry the path because it also
                builds the provider redirect URI.
            email: An [EmailConfig][crudauth.email.config.EmailConfig] to enable
                verify/reset/change flows over email (the built-in delivery
                channel); ``None`` disables email delivery. Either ``email`` or
                ``channels`` enables the recovery endpoints.
            channels: Additional [DeliveryChannel][crudauth.email.channel.DeliveryChannel]s
                to route recovery tokens over (SMS, WhatsApp, push, ...). Fired
                alongside the email channel if ``email`` is also set, every channel
                best-effort. With ``channels`` and no ``email``, the recovery
                endpoints still mount (token lifetimes fall back to the defaults).
                Both ``email`` and ``channels`` need a recovery factor
                (``identity.recovery``).
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
            redis_url: Redis URL for every server-side store: sessions and CSRF
                tokens, the one-time-token and OAuth-state stores, and the default
                rate limiter. A part configured directly (a ``SessionTransport``
                with its own ``backend``/``redis_url``/``redis_client``, or
                ``rate_limiter=``) keeps its own setting. Mutually exclusive with
                ``redis_client``.
            redis_client: An existing async Redis client to use the same way as
                ``redis_url``, with either ``decode_responses`` setting. The caller
                owns it, so ``shutdown()`` doesn't close it. Mutually exclusive with
                ``redis_url``.
            database_store: A [DatabaseStore][crudauth.storage.backends.database.DatabaseStore]
                to keep every server-side store in, the way ``redis_url`` does with
                Redis: sessions and CSRF tokens, the one-time-token, OAuth-state and
                MFA stores, and the default rate limiter (so login lockout is
                counted across workers too). For several workers on a database
                without Redis. A part configured directly keeps its own setting.
                Mutually exclusive with ``redis_url`` and ``redis_client``.
            rate_limit_prefix: The key prefix of the default rate limiter built from
                ``redis_url``, ``redis_client`` or ``database_store``, in place of its
                own (``"crudauth:rl:"`` on Redis, none in the database). Two apps
                sharing one Redis or counter table (an admin panel beside the main
                app) need different ones, or failures in one lock the same username
                or IP out of the other. Can't be combined with ``rate_limiter=``,
                which carries its own.
            rate_limits: Per-action overrides merged over
                :data:`~crudauth.ratelimit.DEFAULT_RATE_LIMITS`. Keys must be
                built-in actions; a custom action takes its limit in
                ``auth.rate_limit(action, RateLimit(...))``.
            lockout: [LockoutConfig][crudauth.ratelimit.config.LockoutConfig] for the
                escalating login lockout shared by ``/login`` and ``/token``,
                whichever transports are configured. Defaults to ``LockoutConfig()``.
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
            mfa: Enable TOTP two-factor authentication with this
                [MfaConfig][crudauth.mfa.config.MfaConfig]. The model needs the MFA
                columns (``make_auth_identity(mfa=True)``) and ``cryptography``
                (``crudauth[mfa]``). Exposes ``auth.mfa`` and the ``/mfa`` routes.
            warn_on_memory_backend: Log a startup warning when an in-memory
                backend is active (the zero-config default). In-memory state is
                per-process, so under multiple workers it silently breaks; set
                ``False`` to silence once you've accepted that (e.g. single-worker
                dev).
            password_policy: The [PasswordPolicy][crudauth.password.PasswordPolicy] every
                new password must meet on registration, set, change and reset. The
                default requires at least 8 characters.
            legacy_verifiers: Checks for password hashes another system wrote, for
                an app moving its users onto crudauth. When crudauth's own check fails
                at login, each runs in turn; a match signs the user in and replaces the
                stored hash with a crudauth one, so it's needed only until every user
                has signed in once. [verify_plain_bcrypt][crudauth.utils.verify_plain_bcrypt]
                covers hashes made by plain bcrypt. Each verifier is
                ``(plain_password, hashed_password) -> bool``, runs in a worker thread,
                and runs for an unknown user too (against a dummy hash), so it can't
                reveal which accounts exist.

        Raises:
            ValueError: If ``SECRET_KEY`` is empty; if ``oauth`` or ``sudo`` is
                set without a session transport (and ``oauth`` also needs
                ``redirect_base_url``); if a configured OAuth provider has no
                ``{provider}_id`` column on the user model; if ``email`` or
                ``channels`` is set with ``identity.recovery=None``; if
                ``rate_limits`` names an unknown action; or if ``lockout`` is set
                alongside a ``SessionTransport``'s ``login_*`` arguments.
        """
        if not SECRET_KEY:
            raise ValueError("SECRET_KEY is required")
        if database_store is not None and (redis_url is not None or redis_client is not None):
            raise ValueError(
                "database_store can't be combined with redis_url or redis_client: "
                "pick one place to keep server-side state"
            )
        if redis_client is not None and redis_url is not None:
            raise ValueError("redis_url and redis_client are mutually exclusive")
        if rate_limit_prefix is not None and rate_limiter is not None:
            raise ValueError(
                "rate_limit_prefix can't be combined with rate_limiter: "
                "give the backend you pass its own prefix"
            )
        self.session = session
        self.password_policy = password_policy or PasswordPolicy()
        self.identity = identity or IdentityConfig()
        self.repo = UserRepository(
            user_model,
            column_map,
            register_extra_fields,
            login_fields=self.identity.login,
            recovery=self.identity.recovery,
        )
        self._validate_identity(oauth=oauth, email=email, channels=channels)
        self.hooks = hooks or AuthHooks()
        self.new_user_fields = new_user_fields
        self.new_user_defaults = self.repo.filter_provisioning_data(new_user_defaults or {})
        self._register_schema = register_schema
        self._warn_on_register_extra_fields(register_extra_fields)
        self._warn_on_privileged_register_fields(register_schema)
        self._rate_limits = self._merge_rate_limits(rate_limits)

        self.transports: list[Transport] = list(transports) if transports else [SessionTransport()]
        self._session_transport = self._first_transport(SessionTransport)
        self._bearer_transport = self._first_transport(BearerTransport)
        self._owned_redis = redis_client_from_url(redis_url) if redis_url is not None else None
        self.runtime = self._build_runtime(
            secret_key=SECRET_KEY,
            redirect_base_url=redirect_base_url,
            algorithm=algorithm,
            cookies=cookies,
            redis_client=redis_client if redis_client is not None else self._owned_redis,
            rate_limiter=rate_limiter,
            lockout=lockout,
            trusted_proxy_hops=trusted_proxy_hops,
            database_store=database_store,
            rate_limit_prefix=rate_limit_prefix,
            legacy_verifiers=tuple(legacy_verifiers or ()),
        )
        self._principals = PrincipalResolver(self.runtime)
        for transport in self.transports:
            transport.bind(self.runtime)

        self._stores: list[tuple[str, AbstractSessionStorage[Any]]] = []
        self.sudo: SudoManager | None = None
        self._email_service: EmailFlowService | None = None
        self._oauth_service: OAuthAccountService | None = None
        self._oauth_router: APIRouter | None = None
        self._oauth_providers: dict[str, AbstractOAuthProvider] = {}
        if mfa is not None:
            self._build_mfa(mfa)
        if sudo is not None:
            self._build_sudo(sudo)
        if email is not None or channels:
            self._build_email(email, channels)
        if oauth:
            self._build_oauth(
                oauth, redirect_base_url, oauth_paths, oauth_response_mode, oauth_default_redirect
            )

        if oauth and mfa is not None:
            self._warn_on_oauth_skipping_required_mfa(mfa)
        if warn_on_memory_backend:
            self._warn_on_memory_backend()

    # --- configuration -------------------------------------------------------
    @staticmethod
    def _merge_rate_limits(overrides: dict[str, RateLimit] | None) -> dict[str, RateLimit]:
        unknown_actions = sorted(set(overrides or {}) - set(DEFAULT_RATE_LIMITS))
        if unknown_actions:
            raise ValueError(
                f"Unknown rate_limits key(s) {unknown_actions}; expected "
                f"{sorted(DEFAULT_RATE_LIMITS)}. Pass a custom action's limit to "
                "auth.rate_limit(action, RateLimit(...))."
            )
        return {**DEFAULT_RATE_LIMITS, **(overrides or {})}

    def _first_transport(self, kind: type[TransportT]) -> TransportT | None:
        return next((t for t in self.transports if isinstance(t, kind)), None)

    def _build_runtime(
        self,
        *,
        secret_key: str,
        redirect_base_url: str | None,
        algorithm: str,
        cookies: CookieConfig | None,
        redis_client: Any,
        rate_limiter: "RateLimiterBackend | None",
        lockout: LockoutConfig | None,
        trusted_proxy_hops: int,
        database_store: DatabaseStore | None,
        rate_limit_prefix: str | None,
        legacy_verifiers: tuple[LegacyVerifier, ...],
    ) -> AuthRuntime:
        """The state transports and services share, before any transport is bound.

        The rate limiter defaults to Redis when a Redis client is configured, to the
        database when a ``database_store`` is, else memory, and the login lockout is
        built on it here because both transports read ``runtime.lockout`` when they bind.
        A ``rate_limit_prefix`` replaces the Redis or database limiter's own key prefix.
        """
        limiter: "RateLimiterBackend"
        if rate_limiter is not None:
            limiter = rate_limiter
        elif redis_client is not None:
            if rate_limit_prefix is None:
                limiter = redis_rate_limiter(client=redis_client)
            else:
                limiter = redis_rate_limiter(client=redis_client, prefix=rate_limit_prefix)
        elif database_store is not None:
            limiter = database_store.rate_limiter(prefix=rate_limit_prefix or "")
        else:
            limiter = MemoryRateLimiterBackend()
        return AuthRuntime(
            secret_key=secret_key,
            repo=self.repo,
            hooks=self.hooks,
            redirect_base_url=redirect_base_url,
            db_dependency=self.session,
            algorithm=algorithm,
            cookie_config=cookies or CookieConfig(),
            rate_limiter=limiter,
            lockout=self._build_lockout(lockout, limiter),
            trusted_proxy_hops=trusted_proxy_hops,
            redis_client=redis_client,
            transports=self.transports,
            database_store=database_store,
            legacy_verifiers=legacy_verifiers,
        )

    def _build_lockout(
        self, lockout: LockoutConfig | None, rate_limiter: "RateLimiterBackend"
    ) -> LockoutPolicy:
        """Build the one shared login-lockout policy.

        Note:
            The tuning comes from ``lockout=`` or a session transport's ``login_*``
            arguments, else the ``LockoutConfig`` defaults.
        """
        transport_lockout = self._session_transport.lockout if self._session_transport else None
        if lockout is not None and transport_lockout is not None:
            raise ValueError(
                "Login lockout is configured twice: pass either CRUDAuth(lockout=LockoutConfig(...)) "
                "or SessionTransport's login_* arguments, not both."
            )
        config = lockout or transport_lockout or LockoutConfig()
        return LockoutPolicy(rate_limiter, **asdict(config), fail_open=False)

    def _validate_identity(
        self,
        *,
        oauth: dict[str, Any] | None,
        email: Any,
        channels: list[DeliveryChannel] | None,
    ) -> None:
        """Check the identity contract against the model, fail-closed at construction.

        The model owns the shape; this asserts the config agrees with it, so a
        login field that isn't a unique column, a non-unique recovery field, OAuth
        without an email login, recovery delivery without a recovery factor, or an
        email flow on a model with no email column all raise here rather than
        splitting into a silent second source of truth.
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
        if recovery is None and (email is not None or channels):
            raise ValueError(
                "email= and channels= deliver recovery tokens, so they require a recovery "
                "factor; set identity.recovery or drop them."
            )
        if email is not None and not self.repo.has("email"):
            raise ValueError("email=EmailConfig(...) requires an 'email' column on the user model.")

    @staticmethod
    def _warn_on_oauth_skipping_required_mfa(mfa: MfaConfig) -> None:
        if mfa.required is not False and not mfa.oauth:
            logger.warning(
                "crudauth: MfaConfig.required is set but OAuth logins skip MFA "
                "(MfaConfig.oauth=False), so a required account with a linked provider can "
                "sign in without a code. Set MfaConfig(oauth=True) to challenge them."
            )

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

    # --- storage -------------------------------------------------------------
    def _backend_config(self) -> tuple[str, Any]:
        if self.runtime.redis_client is not None:
            return BACKEND_REDIS, self.runtime.redis_client
        if self.runtime.database_store is not None:
            return BACKEND_DATABASE, None
        transport = self._session_transport
        if (
            transport is not None
            and transport.backend is not None
            and transport.backend != BACKEND_CUSTOM
        ):
            return transport.backend, transport.redis_client
        return BACKEND_MEMORY, None

    def _new_store(self, label: str, prefix: str, expiration: int) -> "AbstractSessionStorage[Any]":
        """A store on the configured backend, opened and closed with ``auth``.

        ``label`` names it in the in-memory backend warning.
        """
        backend, redis_client = self._backend_config()
        store = get_session_storage(
            backend,
            prefix=prefix,
            expiration=expiration,
            client=redis_client,
            database=self.runtime.database_store,
        )
        self._stores.append((label, store))
        return store

    def _warn_on_memory_backend(self) -> None:
        """Warn when an in-memory backend is active (the zero-config default).

        In-memory state is per-process: under multiple workers it is not shared,
        so login-lockout counters, sessions/CSRF tokens, and single-use token /
        OAuth-state atomicity silently weaken. Production should use redis.
        """
        memory: list[str] = []
        if isinstance(self.runtime.rate_limiter, MemoryRateLimiterBackend):
            memory.append("rate limiter (lockout/throttle counters)")
        if any(
            isinstance(t, SessionTransport) and t.backend == BACKEND_MEMORY for t in self.transports
        ):
            memory.append("sessions/CSRF")
        for label in (MEMORY_TOKEN_STORES, MEMORY_MFA_STORE):
            if any(
                name == label and isinstance(store, MemorySessionStorage)
                for name, store in self._stores
            ):
                memory.append(label)
        if not memory:
            return
        logger.warning(
            "crudauth: using in-memory backend(s) - %s. In-memory state is per-process, so "
            "under multiple workers it is NOT shared and those guarantees weaken silently. "
            "Pass redis_url= or redis_client= to CRUDAuth in production, or "
            "warn_on_memory_backend=False to silence.",
            ", ".join(memory),
        )

    # --- features ------------------------------------------------------------
    def _require_session_manager(self, message: str) -> SessionManager:
        if self._session_manager is None:
            raise ValueError(message)
        return self._session_manager

    def _build_email(self, email: Any, channels: list[DeliveryChannel] | None) -> None:
        token_store = self._new_store(MEMORY_TOKEN_STORES, "used_token:", USED_TOKEN_TTL_SECONDS)
        self._email_service = EmailFlowService(
            repo=self.repo,
            secret_key=self.runtime.secret_key,
            config=email,
            channels=channels,
            hooks=self.hooks,
            algorithm=self.runtime.algorithm,
            token_store=token_store,
            session_manager=self._session_manager,
            rate_limiter=self.runtime.rate_limiter,
            rate_limits=self._rate_limits,
            password_policy=self.password_policy,
        )
        self.runtime.email_service = self._email_service

    def _build_oauth(
        self,
        oauth: dict[str, Any],
        redirect_base_url: str | None,
        oauth_paths: dict[str, str] | None,
        response_mode: Literal["redirect", "json"],
        default_redirect: str | None,
    ) -> None:
        sessions = self._require_session_manager(
            "OAuth establishes a session on callback; add a SessionTransport to transports=[...]."
        )
        if not redirect_base_url:
            raise ValueError("redirect_base_url is required when oauth=... is configured")
        if default_redirect is not None and not is_redirect_target(default_redirect):
            raise ValueError(
                f"oauth_default_redirect {default_redirect!r} must be a same-origin path "
                "such as '/app/login' or an absolute http(s) URL"
            )
        paths = resolve_oauth_paths(oauth_paths)
        self._oauth_providers = {
            name: self._oauth_provider(
                name, credentials, callback_url(redirect_base_url, paths, name)
            )
            for name, credentials in oauth.items()
        }
        state_storage = self._new_store(
            MEMORY_TOKEN_STORES, "oauth_state:", OAUTH_STATE_TTL_SECONDS
        )
        self._oauth_service = OAuthAccountService(
            self.repo, self.new_user_fields, self.new_user_defaults, session_manager=sessions
        )
        self._oauth_router = build_oauth_router(
            runtime=self.runtime,
            providers=self._oauth_providers,
            state_storage=state_storage,
            account_service=self._oauth_service,
            session_manager=sessions,
            authorize_rate_limit=self.rate_limit("oauth_authorize"),
            default_redirect=default_redirect or redirect_base_url,
            response_mode=response_mode,
            **paths,
        )

    @property
    def oauth_providers(self) -> Mapping[str, AbstractOAuthProvider]:
        """The configured OAuth providers, by the name they were configured under.

        Read-only; the provider objects carry what was resolved for them, such as
        an OIDC provider's discovery document.
        """
        return MappingProxyType(self._oauth_providers)

    def _oauth_provider(
        self, name: str, credentials: OAuthCredentials, redirect_uri: str
    ) -> AbstractOAuthProvider:
        if not self.repo.has(f"{name}_id"):
            raise ValueError(
                f"OAuth provider {name!r} needs a '{name}_id' column on the user model "
                f"to store and match its account id. Add it (e.g. "
                f"'{name}_id: Mapped[str | None] = mapped_column(unique=True, index=True, "
                f"default=None)') or map it via column_map=."
            )
        if credentials.issuer:
            return GenericOIDCProvider(
                credentials.client_id,
                credentials.client_secret,
                redirect_uri,
                issuer=credentials.issuer,
                provider_name=name,
                scopes=credentials.scopes,
            )
        return OAuthProviderFactory.create_provider(
            name,
            client_id=credentials.client_id,
            client_secret=credentials.client_secret,
            redirect_uri=redirect_uri,
            scopes=credentials.scopes,
        )

    def _build_mfa(self, config: MfaConfig) -> None:
        missing = [field for field in MFA_FIELDS if not self.repo.has(field)]
        if missing:
            raise ValueError(
                f"mfa=MfaConfig(...) needs the MFA columns {missing} on the user model. "
                "Use make_auth_identity(mfa=True), or map them via column_map=."
            )
        if self.runtime.secret_key in config.encryption_keys:
            raise ValueError("MfaConfig.encryption_key must differ from SECRET_KEY.")
        challenge_store = self._new_store(
            MEMORY_MFA_STORE, CHALLENGE_STORAGE_PREFIX, config.challenge_ttl_seconds
        )
        self.runtime.mfa = MfaService(
            runtime=self.runtime, config=config, challenge_store=challenge_store
        )

    def _build_sudo(self, config: SudoConfig) -> None:
        self.sudo = SudoManager(
            session_manager=self._require_session_manager(
                "Sudo stamps the elevation on a server-side session; add a "
                "SessionTransport to transports=[...]."
            ),
            repo=self.repo,
            backend=self.runtime.rate_limiter,
            hooks=self.hooks,
            config=config,
            mfa=self.runtime.mfa,
        )

    # --- services ------------------------------------------------------------
    async def validate_password(
        self,
        password: str,
        *,
        user: Any = None,
        source: PasswordSource = "set",
        field: str = "password",
    ) -> None:
        """Check ``password`` against ``password_policy`` before your own code hashes it.

        Raises [PasswordPolicyException][crudauth.exceptions.PasswordPolicyException]
        (422) at ``field`` when it fails. Pass the ``user`` it's for so validators
        taking a [PasswordContext][crudauth.password.PasswordContext] see its username
        and email.
        """
        if user is None:
            context = PasswordContext(source=source)
        else:
            context = PasswordContext.for_user(self.repo, source, user)
        await self.password_policy.enforce(password, context, field=field)

    @property
    def sessions(self):
        """The [SessionManager][crudauth.transports.session.manager.SessionManager] of the configured session transport."""
        if self._session_manager is None:
            raise RuntimeError(
                "Session management requires a SessionTransport in transports=[...]."
            )
        return self._session_manager

    @property
    def _session_manager(self) -> SessionManager | None:
        if self._session_transport is None:
            return None
        return self._session_transport.manager

    @property
    def emails(self) -> "EmailFlowService | None":
        """The [EmailFlowService][crudauth.email.service.EmailFlowService], or ``None`` when no recovery is configured.

        Drives the recovery flows (`request_recovery_verification`, `reset_password`,
        `request_email_change`, ...) so a hand-written route can trigger them with
        the same token mint/verify the built-in endpoints use.

        Example:
            ```python
            if auth.emails is not None:
                await auth.emails.request_password_reset(db, email)
            ```
        """
        return self._email_service

    @property
    def oauth(self) -> "OAuthAccountService | None":
        """The [OAuthAccountService][crudauth.oauth.OAuthAccountService], or ``None`` when OAuth isn't configured.

        Exposes `get_or_create_user` (provider-id → verified-email link → create) so
        a hand-written OAuth callback can reuse the linking/creation rules.

        Example:
            ```python
            if auth.oauth is not None:
                user, created = await auth.oauth.get_or_create_user(info, db)
            ```
        """
        return self._oauth_service

    @property
    def oauth_router(self) -> APIRouter:
        """The configured OAuth routes, for apps keeping their own auth routes."""
        if self._oauth_router is None:
            raise RuntimeError("OAuth is not configured")
        return self._oauth_router

    @property
    def mfa(self) -> MfaService | None:
        """The [MfaService][crudauth.mfa.service.MfaService], or ``None`` when MFA isn't configured."""
        return self.runtime.mfa

    @property
    def rate_limits(self) -> dict[str, RateLimit]:
        """The per-action limits in effect: the defaults with ``rate_limits=`` applied."""
        return dict(self._rate_limits)

    # --- the current_user() factory -----------------------------------------
    async def resolve_principal(
        self, request: Request, update_activity: bool = False
    ) -> Principal | None:
        """Resolve the request principal outside FastAPI dependency injection.

        This is intended for middleware and other request-level code. It tries
        transports in configured order, returns ``None`` for anonymous or
        invalid credentials, does not enforce CSRF, and does not slide sessions
        unless ``update_activity=True``. A later ``current_user()`` in the same
        request reuses the result, reloading the user through its own session.

        It opens its own DB session by calling the ``session`` dependency
        directly, so FastAPI's ``dependency_overrides`` don't apply to it.
        """
        return await self._principals.resolve_outside_dependencies(
            request, self.transports, update_activity=update_activity
        )

    async def authenticate_password(
        self,
        db: Any,
        identifier: str,
        password: str,
        *,
        request: Request,
        record_success: bool = True,
    ) -> Any:
        """Verify a username/email + password with the full login hardening.

        The hardened credential check behind ``/login`` and ``/token``, exposed so
        a hand-written login route gets the same protections (shared escalating
        lockout, timing-equalized verification, disabled-account check) instead of
        reassembling them. Returns the user row; raises ``RateLimitException`` on
        lockout and ``UnauthorizedException`` on bad credentials. Delegates to
        [AuthRuntime.authenticate_password][crudauth.core.AuthRuntime.authenticate_password].

        Example:
            ```python
            @app.post("/my-login")
            async def my_login(request: Request, form: MyForm, db=Depends(get_db)):
                user = await auth.authenticate_password(
                    db, form.username, form.password, request=request
                )
                sid, csrf = await auth.sessions.create_session(request, auth.repo.user_id(user))
                ...
            ```
        """
        return await self.runtime.authenticate_password(
            db, identifier, password, request=request, record_success=record_success
        )

    def issue_tokens(self, user: Any, *, scopes: list[str] | None = None) -> dict[str, Any]:
        """Mint a bearer access (+refresh) token pair for a user.

        The hardened issuance behind ``/token``, exposed for a hand-written token
        endpoint: ``scopes`` are clamped to the transport's ``grantable_scopes``
        (no self-grant) and both tokens carry the ``token_version`` epoch (so a
        password reset revokes them). The refresh token is returned under
        ``refresh_token`` (there's no ``Response`` to set a cookie on). Delegates to
        [BearerTransport.issue_tokens][crudauth.transports.bearer.transport.BearerTransport.issue_tokens].

        Raises:
            RuntimeError: If no [BearerTransport][crudauth.transports.bearer.transport.BearerTransport] is configured.

        Example:
            ```python
            user = await auth.authenticate_password(db, ident, pw, request=request)
            tokens = auth.issue_tokens(user, scopes=["read"])
            ```
        """
        if self._bearer_transport is None:
            raise RuntimeError("issue_tokens requires a BearerTransport")
        return self._bearer_transport.issue_tokens(user, scopes=scopes)

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
        if verified and self.identity.recovery is None:
            raise ValueError(
                "current_user(verified=True) requires a recovery factor (identity.recovery); "
                "an account shape with no recovery has nothing to prove control of."
            )
        selected = self._select_transports(transport)
        required_scopes = list(scopes or [])

        async def dependency(
            request: Request, db: Annotated[Any, Depends(self.session)]
        ) -> Principal | None:
            principal = await self._principals.resolve(request, db, selected)

            if principal is None:
                if optional:
                    return None
                raise UnauthorizedException("Not authenticated")

            if superuser and not principal.is_superuser:
                raise ForbiddenException("Insufficient privileges")
            if verified and not principal.recovery_verified:
                raise ForbiddenException("Recovery factor not verified")
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
        limit: RateLimit | RateLimitResolver | None = None,
        *,
        key: "KeyBy | Callable[..., str]" = KeyBy.IP,
        transport: str | list[str] | None = None,
    ) -> Callable[..., Any]:
        """Build a FastAPI dependency that throttles an endpoint.

        ``limit`` is a ``RateLimit`` or a sync/async function of ``(request, principal)``
        returning one (``None`` for no limit). Without it, ``action`` must be a built-in
        action, and its ``rate_limits=`` override or
        :data:`~crudauth.ratelimit.DEFAULT_RATE_LIMITS` entry applies.
        ``key`` picks who shares a budget: a ``KeyBy`` member, ``key(request)``, or
        ``key(request, principal)``. ``KeyBy.IP`` keys an IPv6 client by its ``/64``
        (see [client_ip_key][crudauth.utils.client_ip_key]). ``transport`` narrows which credentials identify the
        caller, as on [current_user][crudauth.crud_auth.CRUDAuth.current_user]. Writes
        ``X-RateLimit-*`` headers and raises
        [RateLimitException][crudauth.exceptions.RateLimitException] (429) when the caller exceeds the window.

        Example:
            ```python
            @app.post("/contact", dependencies=[Depends(auth.rate_limit("contact", RateLimit(5, 60)))])
            async def contact(...): ...
            ```
        """
        resolved = limit or self._rate_limits.get(action)
        if resolved is None:
            raise ValueError(
                f"No rate limit configured for action {action!r}; pass limit=RateLimit(...)."
            )
        selected = self._select_transports(transport)
        backend = self.runtime.rate_limiter
        if key is KeyBy.USER:
            return limit_by_user(
                backend,
                action=action,
                limit=resolved,
                current_user=self.current_user(transport=transport),
            )

        async def principal(request: Request, db: Any) -> Principal | None:
            return await self._principals.resolve(request, db, selected, enforce_csrf=False)

        return limit_by_request(
            backend,
            action=action,
            limit=resolved,
            key=key,
            trusted_proxy_hops=self.runtime.trusted_proxy_hops,
            session=self.session,
            principal=principal,
        )

    @property
    def rate_limiter(self) -> "RateLimiterBackend | None":
        """The configured rate-limit backend."""
        return self.runtime.rate_limiter

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
        router.include_router(build_register_route(self, self._register_schema))
        router.include_router(build_account_router(self, self._session_manager))
        if self._session_transport is not None and self._session_transport.management_routes:
            router.include_router(build_session_management_router(self, self.sessions))
        for transport in self.transports:
            routes = transport.contributes_routes()
            if routes is not None:
                router.include_router(routes)
        if self._oauth_router is not None:
            router.include_router(self._oauth_router)
        if self._email_service is not None:
            router.include_router(build_email_router(auth=self, service=self._email_service))
        if self.runtime.mfa is not None:
            router.include_router(build_mfa_router(auth=self, service=self.runtime.mfa))
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
        for transport in self.transports:
            await transport.initialize()
        for provider in self._oauth_providers.values():
            await provider.initialize()
        for _, store in self._stores:
            await store.initialize()

    async def shutdown(self) -> None:
        """Close connections. Call in lifespan teardown.

        Every component is closed even when an earlier one fails; the first
        failure is re-raised once all of them were attempted.
        """
        closers: list[Callable[[], Awaitable[None]]] = [t.shutdown for t in self.transports]
        closers.extend(store.close for _, store in self._stores)
        if self.runtime.rate_limiter is not None:
            closers.append(self.runtime.rate_limiter.close)
        if self._owned_redis is not None:
            closers.append(self._owned_redis.aclose)
        errors: list[Exception] = []
        for close in closers:
            try:
                await close()
            except Exception as exc:
                errors.append(exc)
        if errors:
            raise errors[0]
