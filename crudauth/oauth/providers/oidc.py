"""Generic OpenID Connect provider, configured from an issuer via discovery.

Unlike Google/GitHub - which hardcode their endpoints - any spec-compliant OIDC
provider (Zitadel, Keycloak, Authentik, Auth0, Okta, Entra ID, ...) is described
entirely by its issuer's discovery document. ``from_discovery`` fetches that
document once and resolves the authorize/token/userinfo endpoints, so a caller
only supplies the issuer + credentials.

Why a classmethod and not just ``__init__``: discovery is an async HTTP call, but
the base port's ``get_authorization_url`` is synchronous and ``__init__`` cannot
``await``. Resolving the endpoints *before* construction keeps the whole sync
surface of the port intact - by the time any method runs, the endpoints are
concrete. Call it once at startup (where ``await`` is available) and reuse the
instance for the process.
"""

from __future__ import annotations

from typing import Any

from ...exceptions import BadRequestException
from ..constants import (
    OAUTH_HTTP_TIMEOUT_SECONDS,
    OIDC_DEFAULT_SCOPES,
    OIDC_DISCOVERY_PATH,
)
from ..provider import AbstractOAuthProvider, _require_httpx
from ..schemas import OAuthUserInfo

__all__ = ["GenericOIDCProvider"]


class GenericOIDCProvider(AbstractOAuthProvider):
    """An OIDC provider whose endpoints come from the issuer's discovery document.

    Construct it with [from_discovery][crudauth.oauth.providers.oidc.GenericOIDCProvider.from_discovery]
    rather than calling ``__init__`` directly. The ``provider_name`` you pass is
    what gets stored as the OAuth identity's provider, so it also determines the
    ``{provider_name}_id`` column the account is linked on (e.g. ``"zitadel"`` ->
    ``zitadel_id``). ``process_user_info`` reads the standard OIDC claims, which
    every conformant provider returns from ``/userinfo``.
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
        issuer: str | None = None,
        discovery_document: dict[str, Any] | None = None,
    ):
        super().__init__(
            client_id,
            client_secret,
            redirect_uri,
            scopes=scopes,
            authorize_endpoint=authorize_endpoint,
            token_endpoint=token_endpoint,
            userinfo_endpoint=userinfo_endpoint,
            provider_name=provider_name,
        )
        # Kept for callers that want to validate id_tokens (jwks_uri) or build a
        # logout URL (end_session_endpoint) later; the login flow itself uses only
        # the three endpoints above.
        self.issuer = issuer
        self.discovery_document = discovery_document or {}

    @classmethod
    async def from_discovery(
        cls,
        issuer: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        *,
        provider_name: str = "oidc",
        scopes: list[str] | None = None,
        transport: Any | None = None,
    ) -> GenericOIDCProvider:
        """Build a provider by fetching ``{issuer}/.well-known/openid-configuration``.

        Args:
            issuer: The OIDC issuer (instance base URL). A trailing slash is ignored.
            provider_name: Identity/column name for the linked account (``zitadel`` ->
                ``zitadel_id``). Defaults to ``"oidc"``.
            scopes: Override the default ``openid profile email``.
            transport: Optional ``httpx`` transport, for tests (inject a
                ``MockTransport`` to avoid the network).

        Raises:
            ValueError: If the document is missing a required endpoint, or its
                ``issuer`` does not match the requested one (a spec requirement -
                guards against a tampered/mismatched discovery document).
            httpx.HTTPStatusError: If the discovery endpoint returns an error status.
        """
        issuer = issuer.rstrip("/")
        httpx = _require_httpx()
        url = f"{issuer}{OIDC_DISCOVERY_PATH}"
        async with httpx.AsyncClient(timeout=OAUTH_HTTP_TIMEOUT_SECONDS, transport=transport) as client:
            resp = await client.get(url, headers={"Accept": "application/json"})
            resp.raise_for_status()
            doc = resp.json()

        for key in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint"):
            if not doc.get(key):
                raise ValueError(f"OIDC discovery at {url} is missing '{key}'.")

        doc_issuer = str(doc.get("issuer", "")).rstrip("/")
        if doc_issuer and doc_issuer != issuer:
            raise ValueError(
                f"OIDC discovery issuer mismatch: requested {issuer!r}, document declares {doc_issuer!r}."
            )

        return cls(
            client_id,
            client_secret,
            redirect_uri,
            scopes=scopes or list(OIDC_DEFAULT_SCOPES),
            authorize_endpoint=doc["authorization_endpoint"],
            token_endpoint=doc["token_endpoint"],
            userinfo_endpoint=doc["userinfo_endpoint"],
            provider_name=provider_name,
            issuer=doc_issuer or issuer,
            discovery_document=doc,
        )

    async def process_user_info(self, user_info: dict[str, Any]) -> OAuthUserInfo:
        """Normalize standard OIDC userinfo claims into ``OAuthUserInfo``.

        Raises if ``sub`` is missing rather than coercing ``None`` into a real
        ``provider_user_id`` (mirrors the built-in providers). ``email_verified``
        rides the claim honestly - auto-linking to an existing account needs it.
        """
        sub = user_info.get("sub")
        if sub is None:
            raise BadRequestException(f"{self.provider_name} did not return a subject (sub).")
        return OAuthUserInfo(
            provider=self.provider_name,
            provider_user_id=str(sub),
            email=user_info.get("email"),
            email_verified=bool(user_info.get("email_verified", False)),
            name=user_info.get("name"),
            given_name=user_info.get("given_name"),
            family_name=user_info.get("family_name"),
            username=user_info.get("preferred_username"),
            picture=user_info.get("picture"),
            raw_data=user_info,
        )
