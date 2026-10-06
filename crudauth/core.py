"""Core extension points: [Transport][crudauth.core.Transport], [AuthContext][crudauth.core.AuthContext], runtime glue.

A *transport* is an authentication channel - cookies (session), ``Authorization:
Bearer`` (bearer), ``X-API-Key`` (api key), and so on. Each one implements the
same two-method port and returns the same [Principal][crudauth.principal.Principal]. The
facade tries configured transports in order, first-credential-wins.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Literal

from fastapi import APIRouter, Request, Response

from .constants import DEFAULT_ALGORITHM
from .exceptions import RateLimitException, UnauthorizedException
from .hooks import HookContext
from .principal import Principal
from .utils import (
    LegacyVerifier,
    get_client_ip,
    get_password_hash_async,
    verify_and_update_password_async,
    verify_legacy_password_async,
)

logger = logging.getLogger("crudauth")

SameSite = Literal["lax", "strict", "none"]

if TYPE_CHECKING:  # pragma: no cover
    from sqlalchemy.ext.asyncio import AsyncSession

    from .email.service import EmailFlowService
    from .hooks import AuthHooks
    from .mfa.service import MfaService
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
        redis_client: The app-wide async Redis client every Redis-capable component
            uses unless it's configured directly: the one ``CRUDAuth`` built from
            ``redis_url``, or the caller's ``redis_client``.
        transports: Every configured transport, in precedence order.
        mfa: The [MfaService][crudauth.mfa.service.MfaService], or ``None`` when MFA
            isn't configured.
        legacy_verifiers: Checks for password hashes another system wrote, tried at
            login when crudauth's own check fails; a match is rehashed in crudauth's
            format.

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
    redis_client: Any = None
    transports: list[Transport] = field(default_factory=list)
    mfa: "MfaService | None" = None
    legacy_verifiers: tuple[LegacyVerifier, ...] = ()

    def clear_cookies(self, response: Response) -> None:
        """Expire the cookie credentials of every configured transport, for a logout."""
        for transport in self.transports:
            transport.clear_cookies(response)

    async def authenticate_password(
        self,
        db: "AsyncSession",
        identifier: str,
        password: str,
        *,
        request: Request,
        record_success: bool = True,
    ) -> Any:
        """Verify a username/email + password with the full login hardening.

        This is the hardened credential check behind ``/login`` and ``/token``,
        exposed so a hand-written login route gets the same protections instead of
        reassembling them: the shared escalating lockout (keyed by IP + identifier,
        so it can't be sidestepped), timing-equalized verification (no
        user-enumeration oracle), and the disabled-account check. Returns the user
        row on success - the caller then establishes a session or mints a token.
        A stored hash made before Unicode normalization is replaced with a
        normalized one on a successful login, and so is a hash only one of the
        ``legacy_verifiers`` accepts.

        A refusal runs the ``on_lockout`` or ``on_login_failed`` hook before it
        raises; both get the identifier as typed, which the hook must treat as
        untrusted input.

        With ``record_success=False`` a correct password neither clears the lockout
        counters nor counts against them, for a login that still needs its second
        factor; call [record_login_success][crudauth.core.AuthRuntime.record_login_success]
        once the login completes.

        Raises:
            RateLimitException: The lockout is engaged for this IP/identifier.
            UnauthorizedException: Unknown identifier, wrong password, or a disabled
                account - all reported with the same generic message.

        Example:
            ```python
            @app.post("/my-login")
            async def my_login(request: Request, form: MyForm, db=Depends(get_db)):
                user = await auth.runtime.authenticate_password(
                    db, form.username, form.password, request=request
                )
                # ... now establish your own session or issue your own token
            ```
        """
        ip = get_client_ip(request, self.trusted_proxy_hops)
        context = HookContext(
            ip_address=ip, user_agent=request.headers.get("user-agent"), request=request
        )
        if self.lockout is not None:
            allowed, _, retry_after = await self.lockout.check_and_record(
                ip, identifier, success=False
            )
            if not allowed:
                await self.hooks.run_lockout(identifier, retry_after=retry_after, context=context)
                raise RateLimitException(
                    "Too many login attempts. Try again later.", retry_after=retry_after
                )
        user = await self.repo.resolve_login(db, identifier)
        hashed_password = None if user is None else self.repo.get(user, "hashed_password")
        verified, new_hash = await verify_and_update_password_async(password, hashed_password)
        if not verified and self.legacy_verifiers:
            verified = await verify_legacy_password_async(
                self.legacy_verifiers, password, hashed_password
            )
            if verified:
                new_hash = await get_password_hash_async(password)
        if user is None or not verified:
            await self.hooks.run_login_failed(
                identifier,
                user=None if user is None else self.repo.to_dict(user),
                reason="invalid_credentials",
                context=context,
            )
            raise UnauthorizedException("Incorrect username or password")
        if not self.repo.is_active(user):
            logger.warning("login denied: account disabled (user_id=%s)", self.repo.user_id(user))
            await self.hooks.run_login_failed(
                identifier, user=self.repo.to_dict(user), reason="inactive", context=context
            )
            raise UnauthorizedException("Incorrect username or password")
        if new_hash is not None:
            await self.repo.update(db, user, {"hashed_password": new_hash})
        if record_success:
            await self.record_login_success(ip, identifier)
        elif self.lockout is not None:
            await self.lockout.forget_attempt(ip, identifier)
        return user

    async def record_login_success(self, ip_address: str, identifier: str) -> None:
        """Clear the login lockout pressure a completed login earned."""
        if self.lockout is not None:
            await self.lockout.check_and_record(ip_address, identifier, success=True)


@dataclass
class AuthContext:
    """Per-request context passed to [Transport.authenticate][crudauth.core.Transport.authenticate]."""

    request: Request
    db: "AsyncSession"
    runtime: AuthRuntime
    enforce_csrf: bool = True
    update_activity: bool = True
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
            recovery_verified=self.repo.recovery_verified(user) if user is not None else False,
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

    async def revalidate(self, request: Request, principal: Principal, ctx: AuthContext) -> bool:
        """Re-check a principal this transport resolved earlier in the same request.

        Called when a later ``current_user()`` reuses a principal that was
        resolved with fewer checks, e.g. by ``auth.resolve_principal`` in
        middleware. ``ctx.enforce_csrf`` and ``ctx.update_activity`` say which
        checks are still missing. Return ``False`` if the credential is no longer
        valid; raise, like ``authenticate``, for one that must hard-fail. The
        default has nothing to re-check.
        """
        return True

    def contributes_routes(self) -> APIRouter | None:
        """Return an `APIRouter` of endpoints this transport adds, or ``None``."""
        return None

    def clear_cookies(self, response: Response) -> None:
        """Expire the cookies this transport sets on the client, called on logout.

        The default sets no cookies, so it clears none.
        """

    @property
    def sets_cookies(self) -> bool:
        """Whether a completed login sets a cookie, so a cross-site request must not complete it."""
        return False

    async def complete_login(
        self, request: Request, response: Response, user: Any, options: dict[str, Any]
    ) -> dict[str, Any]:
        """Issue this transport's credential for a user whose login is fully verified.

        ``/login`` and ``/token`` end here, and so does ``/mfa/verify`` once the code
        checks out, with the ``options`` the login started with. Fires
        ``on_after_login`` and returns the response body. The default raises, since a
        transport without a login route has nothing to issue.
        """
        raise NotImplementedError(f"The {self.name!r} transport doesn't issue login credentials.")

    async def initialize(self) -> None:
        """Open connections / start background work. Called from ``auth.initialize()``."""

    async def shutdown(self) -> None:
        """Release resources. Called from ``auth.shutdown()``."""
