"""Builds the ``/oauth/{provider}/authorize`` and ``/oauth/{provider}/callback`` routes."""

from collections.abc import Callable
from typing import TYPE_CHECKING, Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, RedirectResponse, Response

from ..constants import OAUTH_STATE_TTL_SECONDS
from ..core import AuthRuntime
from ..exceptions import BadRequestException, OAuthAccountException
from ..hooks import HookContext
from ..storage.base import AbstractSessionStorage
from ..utils import get_client_ip, safe_redirect_path
from .constants import ACCOUNT_INACTIVE, INVALID_STATE, OAUTH_FAILED, OAUTH_STATE_COOKIE_NAME
from .provider import AbstractOAuthProvider, _require_httpx
from .schemas import OAuthState
from .service import OAuthAccountService

if TYPE_CHECKING:  # pragma: no cover
    from ..transports.session.manager import SessionManager

__all__ = ["build_oauth_router"]


def _user_payload(user: Any, repo: Any) -> dict[str, Any]:
    """The identity fields ``/me`` returns, for the JSON callback response."""
    return jsonable_encoder(
        {
            "user_id": repo.user_id(user),
            "username": repo.get(user, "username"),
            "email": repo.get(user, "email"),
            "is_superuser": repo.is_superuser(user),
        }
    )


def build_oauth_router(
    *,
    runtime: AuthRuntime,
    providers: dict[str, AbstractOAuthProvider],
    state_storage: AbstractSessionStorage[OAuthState],
    account_service: OAuthAccountService,
    session_manager: "SessionManager",
    authorize_rate_limit: Callable[..., Any],
    default_redirect: str = "/",
    prefix: str = "/oauth",
    authorize_path: str = "/{provider}/authorize",
    callback_path: str = "/{provider}/callback",
    response_mode: Literal["redirect", "json"] = "redirect",
) -> APIRouter:
    """Build the ``/oauth/{provider}/authorize`` and ``/callback`` router.

    Args:
        runtime: The bound [AuthRuntime][crudauth.core.AuthRuntime] (db dependency, repo, hooks).
        providers: Configured ``{name: provider}`` instances.
        state_storage: TTL'd store for the per-request OAuth state + PKCE.
        account_service: Links/provisions the user from the provider profile.
        session_manager: Establishes the session on a successful callback.
        authorize_rate_limit: Dependency throttling ``authorize``, which writes
            a state entry per request.
        default_redirect: Fallback post-login target when ``redirect_to`` is
            absent or not a safe same-origin path.

    Returns:
        An `APIRouter` mounted under ``prefix``.
    """
    if response_mode not in ("redirect", "json"):
        raise ValueError("response_mode must be 'redirect' or 'json'")
    for path_template in (authorize_path, callback_path):
        if "{provider}" not in path_template:
            raise ValueError(f"OAuth path {path_template!r} must contain '{{provider}}'")
    router = APIRouter(prefix=prefix, tags=["oauth"])
    db_dep = runtime.db_dependency

    def _provider(name: str) -> AbstractOAuthProvider:
        provider = providers.get(name)
        if provider is None:
            raise BadRequestException(f"Unknown or unconfigured OAuth provider: {name!r}")
        return provider

    def _set_state_cookie(response: Any, state_value: str) -> None:
        response.set_cookie(
            OAUTH_STATE_COOKIE_NAME,
            state_value,
            max_age=OAUTH_STATE_TTL_SECONDS,
            httponly=True,
            secure=session_manager.cookie_secure,
            samesite="lax",
            path=session_manager.cookie_path,
        )

    def _clear_state_cookie(response: Any) -> None:
        response.delete_cookie(OAUTH_STATE_COOKIE_NAME, path=session_manager.cookie_path)

    def _error_response(code: str = OAUTH_FAILED) -> Any:
        """Return a JSON 400 or redirect carrying the error ``code``."""
        if response_mode == "json":
            resp = JSONResponse({"detail": code}, status_code=400)
            _clear_state_cookie(resp)
            return resp
        sep = "&" if "?" in default_redirect else "?"
        redirect = RedirectResponse(url=f"{default_redirect}{sep}error={code}", status_code=307)
        _clear_state_cookie(redirect)
        return redirect

    def _invalid_state() -> Any:
        """Refuse a state this browser didn't start, or one that's no longer stored.

        No session is created either way. In redirect mode the browser goes back
        to the app with ``?error=invalid_state``, since the usual causes are a
        sign-in that outlived its state or finished in another browser.
        """
        if response_mode == "json":
            raise BadRequestException("Invalid or expired OAuth state")
        return _error_response(INVALID_STATE)

    @router.get(authorize_path, dependencies=[Depends(authorize_rate_limit)])
    async def authorize(
        provider: str,
        redirect_to: Annotated[str | None, Query()] = None,
    ):
        """Start the OAuth flow: stash state + PKCE and redirect to the provider.

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
        if response_mode == "json":
            result = JSONResponse({"url": auth_data["url"]})
            _set_state_cookie(result, auth_data["state"])
            return result
        redirect = RedirectResponse(url=auth_data["url"], status_code=307)
        _set_state_cookie(redirect, auth_data["state"])
        return redirect

    @router.get(callback_path)
    async def callback(
        provider: str,
        request: Request,
        db: Annotated[Any, Depends(db_dep)],
        code: Annotated[str | None, Query()] = None,
        state: Annotated[str | None, Query()] = None,
        error: Annotated[str | None, Query()] = None,
    ):
        """Handle the provider callback: verify state/PKCE, link-or-create the
        user, start a session, and redirect to the validated target.

        Once the account is resolved and found active, ``on_oauth_login`` gets the
        provider's profile and ``db``, before any MFA challenge and before the
        session is created.

        Note:
            The ``state`` must match the browser-bound cookie set at
            ``authorize`` (login-CSRF / fixation defense), and is then consumed
            with an atomic ``get_and_delete`` so two concurrent callbacks can't
            both redeem the same state+code pair.

        Note:
            Non-success callbacks return a JSON 400 with the error code as
            ``detail`` (in JSON mode) or redirect to the post-login default with
            ``?error=<code>``. ``oauth_failed`` covers a provider-reported
            ``?error=...``, a malformed callback, a token-exchange or userinfo
            failure, and a payload the provider can't parse. ``invalid_state``
            covers a state that doesn't match the browser's cookie or is no longer
            stored (in JSON mode that one stays a 400 with the message
            "Invalid or expired OAuth state"). Account resolution reports the
            [OAuthAccountException][crudauth.exceptions.OAuthAccountException]
            code, and a disabled account reports ``account_inactive``.
        """
        prov = _provider(provider)
        if error or not code or not state:
            return _error_response()
        bound = request.cookies.get(OAUTH_STATE_COOKIE_NAME)
        if not bound or bound != state:
            return _invalid_state()
        state_data = await state_storage.get_and_delete(state, OAuthState)
        if state_data is None or state_data.provider != provider:
            return _invalid_state()

        httpx = _require_httpx()
        try:
            token = await prov.exchange_code(code, code_verifier=state_data.code_verifier)
            access_token = token.get("access_token") if isinstance(token, dict) else None
            if not access_token:
                return _error_response()
            raw = await prov.get_user_info(access_token)
            if not isinstance(raw, dict):
                return _error_response()
            info = await prov.process_user_info(raw)
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            return _error_response()

        try:
            user, created = await account_service.get_or_create_user(info, db)
        except OAuthAccountException as exc:
            return _error_response(exc.code)

        if created:
            await runtime.hooks.run_after_register(
                runtime.repo.to_dict(user),
                db=db,
                context=HookContext(transport="oauth", request=request),
            )
            await runtime.repo.refresh_if_expired(db, user)
        if not runtime.repo.is_active(user):
            return _error_response(ACCOUNT_INACTIVE)

        await runtime.hooks.run_oauth_login(
            runtime.repo.to_dict(user),
            info,
            db=db,
            created=created,
            context=HookContext(
                ip_address=get_client_ip(request, runtime.trusted_proxy_hops),
                user_agent=request.headers.get("user-agent"),
                transport="oauth",
                request=request,
            ),
        )
        await runtime.repo.refresh_if_expired(db, user)

        redirect_url = safe_redirect_path(state_data.redirect_to, default=default_redirect)
        if runtime.mfa is not None and runtime.mfa.config.oauth:
            challenge = await runtime.mfa.challenge_login(
                db,
                user,
                request=request,
                transport="session",
                lockout_identifier=f"oauth:{runtime.repo.user_id(user)}",
                options={
                    "metadata": {"login_type": "oauth", "oauth_provider": provider},
                    "redirect_to": redirect_url,
                },
            )
            if challenge is not None:
                challenged: Response
                if response_mode == "json":
                    challenged = JSONResponse(challenge)
                else:
                    challenged = RedirectResponse(
                        url=f"{default_redirect}#mfa_challenge={challenge['challenge']}",
                        status_code=307,
                    )
                _clear_state_cookie(challenged)
                return challenged

        session_id, csrf = await session_manager.create_session(
            request,
            user_id=runtime.repo.user_id(user),
            metadata={"login_type": "oauth", "oauth_provider": provider},
            token_version=runtime.repo.token_version(user),
        )

        await runtime.hooks.run_after_login(
            runtime.repo.to_dict(user),
            request=request,
            context=HookContext(
                transport="oauth",
                request=request,
                session_handle=session_manager.session_handle(session_id),
            ),
        )
        if response_mode == "json":
            result = JSONResponse(
                {
                    "user": _user_payload(user, runtime.repo),
                    "csrf_token": csrf,
                    "redirect_to": redirect_url,
                }
            )
            session_manager.set_session_cookies(result, session_id, csrf)
            _clear_state_cookie(result)
            return result
        redirect = RedirectResponse(url=redirect_url, status_code=307)
        session_manager.set_session_cookies(redirect, session_id, csrf)
        _clear_state_cookie(redirect)
        return redirect

    return router
