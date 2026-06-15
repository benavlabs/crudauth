"""Core extension points: [Transport][crudauth.core.Transport], [AuthContext][crudauth.core.AuthContext], runtime glue.

A *transport* is an authentication channel - cookies (session), ``Authorization:
Bearer`` (bearer), ``X-API-Key`` (api key), and so on. Each one implements the
same two-method port and returns the same [Principal][crudauth.principal.Principal]. The
facade tries configured transports in order, first-credential-wins.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Literal

from fastapi import APIRouter, Request

from .constants import DEFAULT_ALGORITHM
from .principal import Principal

# Valid SameSite cookie values, matching Starlette's set_cookie signature.
SameSite = Literal["lax", "strict", "none"]

if TYPE_CHECKING:  # pragma: no cover
    from sqlalchemy.ext.asyncio import AsyncSession

    from .email.service import EmailFlowService
    from .hooks import AuthHooks
    from .ratelimit import LockoutPolicy, RateLimiterBackend
    from .repository import UserRepository

__all__ = ["Transport", "AuthContext", "AuthRuntime", "CookieConfig"]


@dataclass
class CookieConfig:
    """One cookie policy, shared by every transport that sets cookies.

    Configured once on [CRUDAuth][crudauth.crud_auth.CRUDAuth] and threaded through
    [AuthRuntime][crudauth.core.AuthRuntime], so the session cookie and the bearer refresh cookie
    can't silently disagree on ``secure``/``samesite``. A transport may still be
    handed its own ``CookieConfig`` to override the app-wide default.
    """

    secure: bool = True
    samesite: SameSite = "lax"
    path: str = "/"


@dataclass
class AuthRuntime:
    """Shared, facade-owned state handed to every transport via [Transport.bind][crudauth.core.Transport.bind].

    Transports are constructed by the user as lightweight config objects
    (``SessionTransport(backend="redis")``); the facade binds them to this
    runtime so they can reach the secret key, the user repository, hooks, etc.,
    without the user having to wire any of it.

    Attributes:
        secret_key: Key for signing/verifying tokens.
        repo: The user repository (logical-field contract over the app's model).
        hooks: Lifecycle hooks (``on_after_register``, ``on_after_login``, ...).
        redirect_base_url: Base URL for building OAuth redirect URIs.
        email_service: Email flow service, or ``None`` when email isn't configured.
        db_dependency: FastAPI dependency yielding an ``AsyncSession``.
        algorithm: JWT signing algorithm.
        cookie_config: App-wide cookie policy.
        rate_limiter: Pluggable rate-limiter backend.
        lockout: Shared escalating login-lockout policy.
        trusted_proxy_hops: Number of trusted reverse proxies in front of the
            app, used to resolve the client IP from ``X-Forwarded-For``. ``0``
            (default) ignores the header and uses the socket peer.

    Note:
        ``lockout`` is a single shared policy used by BOTH the session ``/login``
        and bearer ``/token`` routes, keyed identically so neither endpoint can
        sidestep the other's failure counter.
    """

    secret_key: str
    repo: "UserRepository"
    hooks: "AuthHooks"
    redirect_base_url: str | None = None
    email_service: "EmailFlowService | None" = None
    db_dependency: Callable[..., Any] | None = None
    algorithm: str = DEFAULT_ALGORITHM
    cookie_config: CookieConfig = field(default_factory=CookieConfig)
    rate_limiter: "RateLimiterBackend | None" = None
    lockout: "LockoutPolicy | None" = None
    trusted_proxy_hops: int = 0


@dataclass
class AuthContext:
    """Per-request context passed to [Transport.authenticate][crudauth.core.Transport.authenticate]."""

    request: Request
    db: "AsyncSession"
    runtime: AuthRuntime
    _cache: dict[Any, Any] = field(default_factory=dict)

    @property
    def repo(self) -> "UserRepository":
        return self.runtime.repo

    async def resolve_user(self, user_id: Any) -> Any | None:
        """Shared identity resolver - load the user row for ``user_id`` (cached per request)."""
        if user_id in self._cache:
            return self._cache[user_id]
        user = await self.repo.get_by_id(self.db, user_id)
        self._cache[user_id] = user
        return user

    def build_principal(
        self,
        *,
        user_id: Any,
        user: Any,
        transport: str,
        scopes: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> Principal:
        """Construct a [Principal][crudauth.principal.Principal], filling status flags from the user row."""
        return Principal(
            user_id=user_id,
            scopes=scopes,
            transport=transport,
            user=user,
            is_superuser=self.repo.is_superuser(user) if user is not None else False,
            email_verified=self.repo.email_verified(user) if user is not None else False,
            metadata=metadata or {},
        )


class Transport(ABC):
    """Base class for authentication transports.

    Implement [authenticate][crudauth.core.Transport.authenticate] (the authn slice) and optionally
    [contributes_routes][crudauth.core.Transport.contributes_routes]. Everything else - identity resolution,
    authorization gates, the ``Principal`` shape - is shared by the facade.

    Attributes:
        name: Stable transport name, surfaced as ``Principal.transport`` and used
            for per-endpoint narrowing (``current_user(transport="session")``).
        _cookie_override: Optional per-transport cookie policy; falls back to the
            app-wide policy when ``None``.

    Example:
        ```python
        class ApiKeyTransport(Transport):
            name = "apikey"

            async def authenticate(self, request, ctx):
                raw = request.headers.get("X-API-Key")
                if not raw:
                    return None
                user = await ctx.resolve_user(lookup_user_id(raw))
                return None if user is None else ctx.build_principal(
                    user_id=ctx.repo.user_id(user), user=user, transport=self.name,
                )
        ```
    """

    name: str = "transport"
    _cookie_override: CookieConfig | None = None

    def bind(self, runtime: AuthRuntime) -> None:
        """Called by [CRUDAuth][crudauth.crud_auth.CRUDAuth] when the transport is registered."""
        self.runtime = runtime

    def cookie_config(self) -> CookieConfig:
        """The effective cookie policy: this transport's override, else app-wide."""
        return self._cookie_override or self.runtime.cookie_config

    @abstractmethod
    async def authenticate(self, request: Request, ctx: AuthContext) -> Principal | None:
        """Authenticate ``request``.

        Returns a [Principal][crudauth.principal.Principal] on success, or ``None`` if this transport's
        credentials are absent (so the facade can try the next transport). Raise
        an HTTP exception only for a *present-but-invalid* credential that should
        hard-fail the request (e.g. a session cookie that fails CSRF).
        """
        raise NotImplementedError

    def contributes_routes(self) -> APIRouter | None:
        """Return an `APIRouter` of endpoints this transport adds, or ``None``."""
        return None

    async def initialize(self) -> None:
        """Open connections / start background work. Called from ``auth.initialize()``."""

    async def shutdown(self) -> None:
        """Release resources. Called from ``auth.shutdown()``."""
