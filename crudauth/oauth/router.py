"""Builds the ``/oauth/{provider}/authorize`` and ``/oauth/{provider}/callback`` routes."""

from typing import TYPE_CHECKING, Annotated, Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import RedirectResponse

from ..constants import OAUTH_STATE_TTL_SECONDS
from ..core import AuthRuntime
from ..exceptions import BadRequestException
from ..hooks import HookContext
from ..storage.base import AbstractSessionStorage
from .constants import OAUTH_STATE_COOKIE_NAME
from .provider import AbstractOAuthProvider, _require_httpx
from .schemas import OAuthState
from .service import OAuthAccountService

if TYPE_CHECKING:  # pragma: no cover
    from ..transports.session.manager import SessionManager

__all__ = ["build_oauth_router"]


def build_oauth_router(
    *,
    runtime: AuthRuntime,
    providers: dict[str, AbstractOAuthProvider],
    state_storage: AbstractSessionStorage[OAuthState],
    account_service: OAuthAccountService,
    session_manager: "SessionManager",
    default_redirect: str = "/",
) -> APIRouter:
    """Build the ``/oauth/{provider}/authorize`` and ``/callback`` router.

    Args:
        runtime: The bound [AuthRuntime][crudauth.core.AuthRuntime] (db dependency, repo, hooks).
        providers: Configured ``{name: provider}`` instances.
        state_storage: TTL'd store for the per-request OAuth state + PKCE.
        account_service: Links/provisions the user from the provider profile.
        session_manager: Establishes the session on a successful callback.
        default_redirect: Fallback post-login target when ``redirect_to`` is
            absent or not a safe same-origin path.

    Returns:
        An `APIRouter` mounted under ``/oauth``.
    """
    router = APIRouter(prefix="/oauth", tags=["oauth"])
    db_dep = runtime.db_dependency

    def _safe_redirect(target: str | None) -> str:
        """Only allow same-origin relative paths, to block open-redirect abuse.

        Accepts a target only when it is a single-slash-rooted relative path with
        no scheme and no host. Rejected: absolute URLs (``https://evil.com``),
        protocol-relative (``//evil.com``), backslash tricks (``/\\evil.com``,
        which several browsers normalize to ``//evil.com``), and anything with
        control characters. Anything rejected falls back to ``default_redirect``.
        """
        if not target or not target.startswith("/") or target.startswith("//"):
            return default_redirect
        if "\\" in target or any(ord(c) < 0x20 for c in target):
            return default_redirect
        parts = urlsplit(target)
        if parts.scheme or parts.netloc:
            return default_redirect
        return target

    def _provider(name: str) -> AbstractOAuthProvider:
        provider = providers.get(name)
        if provider is None:
            raise BadRequestException(f"Unknown or unconfigured OAuth provider: {name!r}")
        return provider

    def _error_redirect() -> RedirectResponse:
        """Redirect to the post-login default with an ``error`` marker.

        Used for any non-success callback (provider error, malformed callback,
        token/userinfo failure) so the browser lands on a clean page instead of a
        422/500. Also clears the state-binding cookie.
        """
        sep = "&" if "?" in default_redirect else "?"
        redirect = RedirectResponse(
            url=f"{default_redirect}{sep}error=oauth_failed", status_code=307
        )
        redirect.delete_cookie(OAUTH_STATE_COOKIE_NAME, path=session_manager.cookie_path)
        return redirect

    @router.get("/{provider}/authorize")
    async def authorize(provider: str, redirect_to: Annotated[str | None, Query()] = None):
        """Start the OAuth flow: stash state + PKCE and 307-redirect to the provider.

        ``redirect_to`` is where the callback sends the browser afterwards (only
        same-origin relative paths are honored).

        Note:
            Sets a short-lived, HttpOnly, ``SameSite=Lax`` cookie holding the
            ``state``. The callback requires it to match the ``state`` query
            param, which binds the flow to the browser that started it - an
            attacker who captures a valid callback URL can't replay it in a
            victim's browser (login CSRF / session fixation).
        """
        prov = _provider(provider)
        auth_data = prov.get_authorization_url()
        state = OAuthState(
            state=auth_data["state"],
            provider=provider,
            code_verifier=auth_data.get("code_verifier"),
            redirect_to=redirect_to,
        )
        await state_storage.create(
            state, session_id=auth_data["state"], expiration=OAUTH_STATE_TTL_SECONDS
        )
        redirect = RedirectResponse(url=auth_data["url"], status_code=307)
        redirect.set_cookie(
            OAUTH_STATE_COOKIE_NAME,
            auth_data["state"],
            max_age=OAUTH_STATE_TTL_SECONDS,
            httponly=True,
            secure=session_manager.cookie_secure,
            samesite="lax",
            path=session_manager.cookie_path,
        )
        return redirect

    @router.get("/{provider}/callback")
    async def callback(
        provider: str,
        request: Request,
        response: Response,
        db: Annotated[Any, Depends(db_dep)],
        code: Annotated[str | None, Query()] = None,
        state: Annotated[str | None, Query()] = None,
        error: Annotated[str | None, Query()] = None,
    ):
        """Handle the provider callback: verify state/PKCE, link-or-create the
        user, start a session, and 307-redirect to the validated target.

        Note:
            The ``state`` must match the browser-bound cookie set at
            ``authorize`` (login-CSRF / fixation defense), and is then consumed
            with an atomic ``get_and_delete`` so two concurrent callbacks can't
            both redeem the same state+code pair.

        Note:
            Non-success callbacks redirect to the post-login default with
            ``?error=oauth_failed`` rather than surfacing a 422/500: a
            provider-reported ``?error=...`` (e.g. the user declined), a malformed
            callback (missing ``code``/``state``), a token-exchange or userinfo
            HTTP failure, a missing ``access_token`` (some providers, e.g. GitHub,
            signal failure with HTTP 200 + an error body), or a userinfo payload
            that breaks the provider's parser (``ValueError``/``KeyError``). The
            intentional policy 400s (no email / unverified-link) still surface.
        """
        prov = _provider(provider)
        if error or not code or not state:
            return _error_redirect()
        bound = request.cookies.get(OAUTH_STATE_COOKIE_NAME)
        if not bound or bound != state:
            raise BadRequestException("Invalid or expired OAuth state")
        state_data = await state_storage.get_and_delete(state, OAuthState)
        if state_data is None or state_data.provider != provider:
            raise BadRequestException("Invalid or expired OAuth state")

        httpx = _require_httpx()
        try:
            token = await prov.exchange_code(code, code_verifier=state_data.code_verifier)
            access_token = token.get("access_token")
            if not access_token:
                return _error_redirect()
            raw = await prov.get_user_info(access_token)
            info = await prov.process_user_info(raw)
        except (httpx.HTTPError, ValueError, KeyError):
            return _error_redirect()

        user, created = await account_service.get_or_create_user(info, db)

        if created:
            await runtime.hooks.run_after_register(
                runtime.repo.to_dict(user),
                db=db,
                context=HookContext(transport="oauth", request=request),
            )

        session_id, csrf = await session_manager.create_session(
            request,
            user_id=runtime.repo.user_id(user),
            metadata={"login_type": "oauth", "oauth_provider": provider},
        )
        redirect_url = _safe_redirect(state_data.redirect_to)
        redirect = RedirectResponse(url=redirect_url, status_code=307)
        session_manager.set_session_cookies(redirect, session_id, csrf)
        redirect.delete_cookie(OAUTH_STATE_COOKIE_NAME, path=session_manager.cookie_path)

        await runtime.hooks.run_after_login(
            runtime.repo.to_dict(user),
            request=request,
            context=HookContext(transport="oauth", request=request),
        )
        return redirect

    return router
