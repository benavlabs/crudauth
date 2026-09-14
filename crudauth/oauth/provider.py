"""``AbstractOAuthProvider`` - the port you subclass to add a provider.

Implements the generic Authorization-Code-with-PKCE dance; concrete providers
only supply endpoints and a ``process_user_info`` mapping.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import urlencode

from .constants import OAUTH_HTTP_TIMEOUT_SECONDS, PKCE_VERIFIER_BYTES, STATE_BYTES
from .schemas import OAuthUserInfo

__all__ = ["AbstractOAuthProvider"]


def _require_httpx():
    try:
        import httpx  # noqa: F401

        return httpx
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "OAuth requires the 'httpx' package. Install with: pip install 'crudauth[oauth]'"
        ) from exc


class AbstractOAuthProvider(ABC):
    """Port for an OAuth provider - implements the Authorization-Code-with-PKCE flow.

    Subclass it, pass the three endpoints + scopes + ``provider_name`` to
    ``super().__init__``, implement [process_user_info][crudauth.oauth.provider.AbstractOAuthProvider.process_user_info], and register it
    with [OAuthProviderFactory][crudauth.oauth.factory.OAuthProviderFactory]. Set ``email_verified`` honestly -
    auto-linking to an existing account requires a verified provider email.

    Note:
        A custom provider named ``"gitlab"`` requires a ``gitlab_id`` column on
        your user model (that's where its account id is stored and matched). Add
        it to your model (or map it via ``column_map=``); [CRUDAuth][crudauth.crud_auth.CRUDAuth]
        raises at startup if a configured provider has no ``{provider}_id``
        column. Only ``google_id``/``github_id`` ship on
        [AuthUserMixin][crudauth.models.mixin.AuthUserMixin].

    Example:
        ```python
        class GitLabOAuthProvider(AbstractOAuthProvider):
            def __init__(self, client_id, client_secret, redirect_uri, scopes=None):
                super().__init__(
                    client_id, client_secret, redirect_uri,
                    scopes=scopes or ["read_user"],
                    authorize_endpoint="https://gitlab.com/oauth/authorize",
                    token_endpoint="https://gitlab.com/oauth/token",
                    userinfo_endpoint="https://gitlab.com/api/v4/user",
                    provider_name="gitlab",
                )

            async def process_user_info(self, info):
                return OAuthUserInfo(
                    provider="gitlab", provider_user_id=str(info["id"]),
                    email=info.get("email"), email_verified=True, raw_data=info,
                )

        OAuthProviderFactory.register_provider("gitlab", GitLabOAuthProvider)
        # ...and add `gitlab_id` to your user model.
        ```
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        *,
        scopes: list[str],
        authorize_endpoint: str,
        token_endpoint: str,
        userinfo_endpoint: str,
        provider_name: str,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self.authorize_endpoint = authorize_endpoint
        self.token_endpoint = token_endpoint
        self.userinfo_endpoint = userinfo_endpoint
        self.provider_name = provider_name

    # --- PKCE / state --------------------------------------------------------
    @staticmethod
    def generate_state() -> str:
        """Return a fresh, URL-safe CSRF ``state`` value."""
        return secrets.token_urlsafe(STATE_BYTES)

    @staticmethod
    def generate_pkce_codes() -> dict[str, str]:
        """Return a PKCE pair: ``{"code_verifier": ..., "code_challenge": ...}`` (S256)."""
        verifier = secrets.token_urlsafe(PKCE_VERIFIER_BYTES)
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        return {"code_verifier": verifier, "code_challenge": challenge}

    # --- authorization URL ---------------------------------------------------
    def get_authorization_url(
        self,
        state: str | None = None,
        pkce: bool = True,
        extra_params: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Build the provider authorization URL and the values to stash server-side.

        Args:
            state: CSRF state to embed; generated if omitted.
            pkce: Include a PKCE challenge (recommended).
            extra_params: Provider-specific query params to merge in (e.g. Google's
                ``access_type``/``prompt``).

        Returns:
            ``{"url": <redirect target>, "state": ..., "code_verifier": ...}`` -
            ``code_verifier`` is present only when ``pkce`` is true and must be
            persisted to verify the callback.
        """
        state = state or self.generate_state()
        params: dict[str, str] = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "state": state,
            "scope": " ".join(self.scopes),
        }
        result: dict[str, str] = {"state": state}
        if pkce:
            codes = self.generate_pkce_codes()
            params["code_challenge"] = codes["code_challenge"]
            params["code_challenge_method"] = "S256"
            result["code_verifier"] = codes["code_verifier"]
        if extra_params:
            params.update(extra_params)
        result["url"] = f"{self.authorize_endpoint}?{urlencode(params)}"
        return result

    # --- token exchange ------------------------------------------------------
    async def exchange_code(
        self,
        code: str,
        code_verifier: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Exchange an authorization ``code`` for tokens at the token endpoint.

        Args:
            code: The authorization code from the callback.
            code_verifier: The stored PKCE verifier (required if PKCE was used).
            headers: Extra request headers (some providers need ``Accept``).

        Returns:
            The provider's raw token response (``access_token``, ...).

        Raises:
            httpx.HTTPStatusError: If the token endpoint returns an error status.

        Note:
            ``client_secret`` is included only when the provider actually has
            one. A public client (PKCE-only, ``token_endpoint_auth_method=none``)
            must not send client authentication - several IdPs reject an empty
            ``client_secret`` outright - and its proof is the PKCE verifier,
            which is sent either way.
        """
        httpx = _require_httpx()
        data = {
            "client_id": self.client_id,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        if self.client_secret:
            data["client_secret"] = self.client_secret
        if code_verifier:
            data["code_verifier"] = code_verifier
        req_headers = {"Accept": "application/json"}
        if headers:
            req_headers.update(headers)
        async with httpx.AsyncClient(timeout=OAUTH_HTTP_TIMEOUT_SECONDS) as client:
            resp = await client.post(self.token_endpoint, data=data, headers=req_headers)
            resp.raise_for_status()
            return resp.json()

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """Fetch the raw user profile from the userinfo endpoint.

        Args:
            access_token: A valid provider access token.

        Returns:
            The provider's raw profile JSON (normalize it in
            [process_user_info][crudauth.oauth.provider.AbstractOAuthProvider.process_user_info]).

        Raises:
            httpx.HTTPStatusError: If the userinfo endpoint returns an error status.
        """
        httpx = _require_httpx()
        async with httpx.AsyncClient(timeout=OAUTH_HTTP_TIMEOUT_SECONDS) as client:
            resp = await client.get(
                self.userinfo_endpoint,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
            resp.raise_for_status()
            return resp.json()

    @abstractmethod
    async def process_user_info(self, user_info: dict[str, Any]) -> OAuthUserInfo:
        """Normalize the provider's raw user payload into [OAuthUserInfo][crudauth.oauth.schemas.OAuthUserInfo]."""
        raise NotImplementedError
