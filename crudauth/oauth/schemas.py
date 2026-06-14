"""OAuth data shapes."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

__all__ = ["OAuthCredentials", "OAuthUserInfo", "OAuthState"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class OAuthCredentials(BaseModel):
    """Client credentials for a provider, supplied via ``oauth={...}``."""

    client_id: str
    client_secret: str
    scopes: list[str] | None = None


class OAuthUserInfo(BaseModel):
    """Normalized profile returned by ``AbstractOAuthProvider.process_user_info``."""

    provider: str
    provider_user_id: str
    email: str | None = None
    email_verified: bool = False
    name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    username: str | None = None
    picture: str | None = None
    raw_data: dict[str, Any] = Field(default_factory=dict)


class OAuthState(BaseModel):
    """Server-side state machine entry, keyed by the random ``state`` value.

    Note:
        ``created_at`` is informational only - expiry is enforced by the storage
        TTL (``OAUTH_STATE_TTL_SECONDS``), not by reading this field. A retrieved
        state is by definition unexpired, mirroring the CSRF-token decision.
    """

    state: str
    provider: str
    code_verifier: str | None = None
    redirect_to: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)
