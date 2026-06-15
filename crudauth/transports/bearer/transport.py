"""The bearer transport: ``Authorization: Bearer <jwt>`` for apps and scripts."""

import logging
from datetime import timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi.security import OAuth2PasswordRequestForm

from ...constants import (
    DEFAULT_ACCESS_TTL_SECONDS,
    DEFAULT_REFRESH_TTL_DAYS,
    SECONDS_PER_DAY,
)
from ...core import AuthContext, AuthRuntime, CookieConfig, Transport
from ...exceptions import RateLimitException, UnauthorizedException
from ...hooks import HookContext
from ...principal import Principal
from ...utils import (
    canonical_identifier,
    dummy_verify_password,
    get_client_ip,
    verify_password,
)
from .constants import (
    REFRESH_LOCATION_BODY,
    REFRESH_LOCATION_COOKIE,
    REFRESH_LOCATIONS,
    REFRESH_TOKEN_NAME,
    TOKEN_TYPE_BEARER,
    TOKEN_VERSION_CLAIM,
)
from .tokens import (
    TokenType,
    create_access_token,
    create_refresh_token,
    is_expired_token,
    verify_token,
)

__all__ = ["BearerTransport"]

logger = logging.getLogger("crudauth.bearer")


class BearerTransport(Transport):
    """Stateless JWT auth.

    Args:
        access_ttl: Access token lifetime in seconds (default 15 min).
        refresh_ttl_days: Refresh token lifetime in days (default 30).
        refresh: Where the refresh token lives - ``"cookie"`` (httpOnly, default)
            or ``"body"`` (returned in the JSON response).
        default_scopes: Scopes granted to password-login tokens when the client
            doesn't request a narrower set.
        grantable_scopes: The maximum set of scopes ``/token`` will ever issue.
            A client's requested scopes are intersected with this set, so a
            client cannot self-grant a scope it asks for. Defaults to
            ``default_scopes`` (clients may only narrow, never widen).
        refresh_cookie_path: ``Path`` for the refresh cookie. Defaults to the
            cookie policy's path (``/``); set it to the refresh endpoint's path
            (e.g. ``"/auth/refresh"``) to stop the cookie riding every request
            and narrow its exposure. Must match where ``/refresh`` is mounted.

    Note:
        Issued scopes are **clamped** to ``grantable_scopes`` - the password
        grant silently drops anything outside the grantable set, so an endpoint
        gated by ``scopes=[...]`` can't be satisfied by a self-granted scope. The
        clamp is re-applied at ``/refresh``, so tightening ``grantable_scopes``
        also drops a removed scope from tokens minted off existing refresh
        tokens (rather than honoring it until the refresh token expires).

    Note:
        Bearer tokens are **stateless** - there is no per-token revocation or
        rotation, so a stolen token is valid until it expires
        (``refresh_ttl_days``, default 30) *unless* the user's credential epoch is
        bumped. A password reset increments the user's ``token_version`` (embedded
        as the ``ver`` claim), which invalidates every outstanding access AND
        refresh token for that user at once. Per-token rotation is a planned
        future addition. (Epoch revocation requires a ``token_version`` column;
        [AuthUserMixin][crudauth.models.mixin.AuthUserMixin] supplies it - a model
        without it simply isn't epoch-revocable.)

    Note:
        ``/token`` shares the escalating login lockout with the session
        ``/login`` route (same ``runtime.lockout``, keyed by ip + username), so a
        client locked out on one endpoint can't brute-force via the other.

    Example:
        ```python
        BearerTransport(access_ttl=900, refresh="cookie")
        ```
    """

    name = "bearer"

    def __init__(
        self,
        *,
        access_ttl: int = DEFAULT_ACCESS_TTL_SECONDS,
        refresh_ttl_days: int = DEFAULT_REFRESH_TTL_DAYS,
        refresh: str = REFRESH_LOCATION_COOKIE,
        default_scopes: list[str] | None = None,
        grantable_scopes: list[str] | None = None,
        refresh_cookie_name: str = REFRESH_TOKEN_NAME,
        refresh_cookie_path: str | None = None,
        cookies: CookieConfig | None = None,
    ):
        if refresh not in REFRESH_LOCATIONS:
            raise ValueError("refresh must be 'cookie' or 'body'")
        self.access_ttl = access_ttl
        self.refresh_ttl_days = refresh_ttl_days
        self.refresh = refresh
        self.default_scopes = tuple(default_scopes or ())
        self.grantable_scopes = (
            frozenset(grantable_scopes)
            if grantable_scopes is not None
            else frozenset(self.default_scopes)
        )
        if not set(self.default_scopes) <= self.grantable_scopes:
            raise ValueError("default_scopes must be a subset of grantable_scopes")
        self.refresh_cookie_name = refresh_cookie_name
        self.refresh_cookie_path = refresh_cookie_path
        self._cookie_override = cookies

    # --- authn ---------------------------------------------------------------
    async def authenticate(self, request: Request, ctx: AuthContext) -> Principal | None:
        """Authenticate an ``Authorization: Bearer`` access token.

        Note:
            Absent or non-bearer header → ``None`` (this transport's credential
            isn't present; the facade tries the next transport). An *expired*
            access token also → ``None``: expiry is the normal steady state of a
            short-lived token, not an attack signal, so it falls through to the
            next transport (e.g. a valid session cookie) and is treated as
            anonymous under ``optional=True``. A *tampered* token (bad signature,
            wrong type, missing ``sub``) → raises ``UnauthorizedException``,
            mirroring the session transport's CSRF hard-fail. A valid token whose
            user no longer exists / is inactive returns ``None`` (account
            vanished, treat as anonymous). A token whose ``ver`` claim is below
            the user's current ``token_version`` (e.g. revoked by a password
            reset) also returns ``None`` - it's superseded, not tampered.
        """
        header = request.headers.get("authorization")
        if not header:
            return None
        scheme, _, token = header.partition(" ")
        if scheme.lower() != TOKEN_TYPE_BEARER or not token:
            return None

        payload = verify_token(
            token, self.runtime.secret_key, TokenType.ACCESS, algorithm=self.runtime.algorithm
        )
        if payload is None:
            if is_expired_token(token, self.runtime.secret_key, algorithm=self.runtime.algorithm):
                return None
            raise UnauthorizedException("Invalid token")

        user = await ctx.resolve_user(payload["sub"])
        if user is None or not ctx.repo.is_active(user):
            return None
        if payload.get(TOKEN_VERSION_CLAIM, 0) != ctx.repo.token_version(user):
            return None

        scopes = tuple(payload.get("scopes") or ())
        return ctx.build_principal(
            user_id=ctx.repo.user_id(user), user=user, transport=self.name, scopes=scopes
        )

    # --- routes --------------------------------------------------------------
    def contributes_routes(self) -> APIRouter:
        router = APIRouter(tags=["auth"])
        runtime = self.runtime
        db_dep = runtime.db_dependency

        @router.post("/token")
        async def issue_token(
            request: Request,
            response: Response,
            form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
            db: Annotated[Any, Depends(db_dep)],
        ):
            """Exchange username/email + password for an access token.

            Returns ``{"access_token", "token_type"}``; the refresh token is set
            as an httpOnly cookie or returned in the body per ``refresh=``.
            Subject to the shared login lockout.

            Note:
                A disabled account returns the same "Incorrect username or
                password" as bad credentials (no exists-but-disabled oracle for a
                credential holder); the real reason is logged server-side
                (``reason=disabled``).
            """
            ip = get_client_ip(request, runtime.trusted_proxy_hops)
            login_id = canonical_identifier(form_data.username)
            lockout = runtime.lockout
            if lockout is not None:
                allowed, _, retry_after = await lockout.check_and_record(
                    ip, login_id, success=False
                )
                if not allowed:
                    raise RateLimitException(
                        "Too many login attempts. Try again later.", retry_after=retry_after
                    )

            user = await runtime.repo.get_by_identifier(db, form_data.username)
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

            if lockout is not None:
                await lockout.check_and_record(ip, login_id, success=True)

            scopes = self._grant_scopes(form_data.scopes)
            body = self._mint(runtime, user, scopes, response)
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
            return body

        @router.post("/refresh")
        async def refresh_token(request: Request, db: Annotated[Any, Depends(db_dep)]):
            """Mint a fresh access token from a valid refresh token (cookie or body)."""
            token = await self._read_refresh(request)
            if not token:
                raise UnauthorizedException("Refresh token missing")
            payload = verify_token(
                token, runtime.secret_key, TokenType.REFRESH, algorithm=runtime.algorithm
            )
            if payload is None:
                raise UnauthorizedException("Invalid or expired refresh token")
            user = await runtime.repo.get_by_id(db, payload["sub"])
            if user is None or not runtime.repo.is_active(user):
                raise UnauthorizedException("Invalid or expired refresh token")
            if payload.get(TOKEN_VERSION_CLAIM, 0) != runtime.repo.token_version(user):
                raise UnauthorizedException("Invalid or expired refresh token")
            scopes = self._clamp_scopes(payload.get("scopes") or ())
            access = create_access_token(
                {
                    "sub": str(runtime.repo.user_id(user)),
                    TOKEN_VERSION_CLAIM: runtime.repo.token_version(user),
                },
                runtime.secret_key,
                expires_delta=timedelta(seconds=self.access_ttl),
                algorithm=runtime.algorithm,
                scopes=list(scopes),
            )
            return {"access_token": access, "token_type": TOKEN_TYPE_BEARER}

        return router

    # --- helpers -------------------------------------------------------------
    def _clamp_scopes(self, scopes: list[str] | tuple[str, ...]) -> tuple[str, ...]:
        """Drop any scope not in ``grantable_scopes`` (the issued ⊆ grantable invariant)."""
        return tuple(s for s in scopes if s in self.grantable_scopes)

    def _grant_scopes(self, requested: list[str] | None) -> tuple[str, ...]:
        """Resolve scopes to issue at ``/token``: the request (or ``default_scopes``
        if none) clamped to ``grantable_scopes``, so a client can only narrow."""
        asked = tuple(requested) if requested else self.default_scopes
        return self._clamp_scopes(asked)

    def _mint(
        self, runtime: AuthRuntime, user: Any, scopes: tuple[str, ...], response: Response
    ) -> dict[str, Any]:
        uid = str(runtime.repo.user_id(user))
        ver = runtime.repo.token_version(user)
        access = create_access_token(
            {"sub": uid, TOKEN_VERSION_CLAIM: ver},
            runtime.secret_key,
            expires_delta=timedelta(seconds=self.access_ttl),
            algorithm=runtime.algorithm,
            scopes=list(scopes),
        )
        refresh = create_refresh_token(
            {"sub": uid, TOKEN_VERSION_CLAIM: ver, "scopes": list(scopes)},
            runtime.secret_key,
            expires_delta=timedelta(days=self.refresh_ttl_days),
            algorithm=runtime.algorithm,
        )
        body = {"access_token": access, "token_type": TOKEN_TYPE_BEARER}
        if self.refresh == REFRESH_LOCATION_COOKIE and response is not None:
            cookies = self.cookie_config()
            response.set_cookie(
                key=self.refresh_cookie_name,
                value=refresh,
                httponly=True,
                secure=cookies.secure,
                samesite=cookies.samesite,
                max_age=self.refresh_ttl_days * SECONDS_PER_DAY,
                path=self.refresh_cookie_path or cookies.path,
            )
        else:
            body[REFRESH_TOKEN_NAME] = refresh
        return body

    async def _read_refresh(self, request: Request) -> str | None:
        cookie = request.cookies.get(self.refresh_cookie_name)
        if cookie:
            return cookie
        if self.refresh == REFRESH_LOCATION_BODY:
            try:
                body = await request.json()
            except Exception:
                return None
            if isinstance(body, dict):
                return body.get(REFRESH_TOKEN_NAME)
        return None
