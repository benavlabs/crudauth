"""GenericOIDCProvider: discovery resolution, validation, and claim normalization."""

from __future__ import annotations

import httpx
import pytest
from fastapi import HTTPException

from crudauth.oauth import GenericOIDCProvider

# A Zitadel-shaped discovery document (same endpoint layout).
DISCOVERY = {
    "issuer": "https://idp.example.com",
    "authorization_endpoint": "https://idp.example.com/oauth/v2/authorize",
    "token_endpoint": "https://idp.example.com/oauth/v2/token",
    "userinfo_endpoint": "https://idp.example.com/oidc/v1/userinfo",
    "jwks_uri": "https://idp.example.com/oauth/v2/keys",
}


def _transport(doc: dict, status: int = 200) -> httpx.MockTransport:
    """A MockTransport that serves ``doc`` at the discovery path (no network)."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/.well-known/openid-configuration"
        return httpx.Response(status, json=doc)

    return httpx.MockTransport(handler)


def _provider(provider_name: str = "zitadel") -> GenericOIDCProvider:
    """A directly-constructed provider (bypasses discovery) for claim-mapping tests."""
    return GenericOIDCProvider(
        "id",
        "sec",
        "https://app/cb",
        scopes=["openid"],
        authorize_endpoint="https://idp.example.com/oauth/v2/authorize",
        token_endpoint="https://idp.example.com/oauth/v2/token",
        userinfo_endpoint="https://idp.example.com/oidc/v1/userinfo",
        provider_name=provider_name,
    )


# --- discovery resolves the three endpoints (trailing slash on issuer is ok) ---
async def test_from_discovery_resolves_endpoints() -> None:
    prov = await GenericOIDCProvider.from_discovery(
        "https://idp.example.com/",  # trailing slash must be tolerated
        "id",
        "sec",
        "https://app/cb",
        provider_name="zitadel",
        transport=_transport(DISCOVERY),
    )
    assert prov.authorize_endpoint == DISCOVERY["authorization_endpoint"]
    assert prov.token_endpoint == DISCOVERY["token_endpoint"]
    assert prov.userinfo_endpoint == DISCOVERY["userinfo_endpoint"]
    assert prov.provider_name == "zitadel"
    assert prov.issuer == "https://idp.example.com"
    assert prov.discovery_document["jwks_uri"] == DISCOVERY["jwks_uri"]


# --- the base PKCE flow rides on top of the discovered endpoints --------------
async def test_from_discovery_authorize_url_uses_pkce_s256() -> None:
    prov = await GenericOIDCProvider.from_discovery(
        "https://idp.example.com", "id", "sec", "https://app/cb", transport=_transport(DISCOVERY)
    )
    auth = prov.get_authorization_url()
    assert auth["url"].startswith("https://idp.example.com/oauth/v2/authorize?")
    assert "code_challenge_method=S256" in auth["url"]
    assert "code_verifier" in auth  # stored server-side to verify the callback


# --- a discovery document missing a required endpoint is rejected -------------
async def test_from_discovery_missing_endpoint_raises() -> None:
    doc = {k: v for k, v in DISCOVERY.items() if k != "token_endpoint"}
    with pytest.raises(ValueError, match="token_endpoint"):
        await GenericOIDCProvider.from_discovery(
            "https://idp.example.com", "id", "sec", "https://app/cb", transport=_transport(doc)
        )


# --- a mismatched issuer in the document is rejected (spec requirement) --------
async def test_from_discovery_issuer_mismatch_raises() -> None:
    doc = {**DISCOVERY, "issuer": "https://evil.example.com"}
    with pytest.raises(ValueError, match="issuer"):
        await GenericOIDCProvider.from_discovery(
            "https://idp.example.com", "id", "sec", "https://app/cb", transport=_transport(doc)
        )


# --- standard OIDC claims map straight through; provider_name is preserved ----
async def test_process_user_info_maps_standard_claims() -> None:
    info = await _provider("zitadel").process_user_info(
        {
            "sub": "z-1",
            "email": "u@x.com",
            "email_verified": True,
            "preferred_username": "user1",
            "name": "User One",
            "given_name": "User",
            "family_name": "One",
            "picture": "https://idp/p.png",
        }
    )
    assert info.provider == "zitadel"  # drives the zitadel_id linking column
    assert info.provider_user_id == "z-1"
    assert info.username == "user1"
    assert info.email_verified is True
    assert info.given_name == "User"


# --- a missing sub raises rather than coercing None into an id ----------------
async def test_process_user_info_missing_sub_raises() -> None:
    with pytest.raises(HTTPException) as exc:
        await _provider().process_user_info({"email": "u@x.com"})  # no "sub"
    assert exc.value.status_code == 400
