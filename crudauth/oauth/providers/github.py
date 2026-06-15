"""GitHub OAuth provider (handles the separate emails endpoint)."""

from __future__ import annotations

from typing import Any

from ...exceptions import BadRequestException
from ..constants import (
    GITHUB,
    GITHUB_AUTHORIZE_ENDPOINT,
    GITHUB_DEFAULT_SCOPES,
    GITHUB_EMAILS_ENDPOINT,
    GITHUB_TOKEN_ENDPOINT,
    GITHUB_USERINFO_ENDPOINT,
    OAUTH_HTTP_TIMEOUT_SECONDS,
)
from ..provider import AbstractOAuthProvider, _require_httpx
from ..schemas import OAuthUserInfo

__all__ = ["GitHubOAuthProvider"]


def _select_github_email(emails: list[dict[str, Any]]) -> tuple[str | None, bool]:
    """Pick the account email + verified flag from GitHub's /user/emails list.

    Preference: primary-and-verified → any verified → primary (unverified) →
    first listed. An unverified primary must NOT silently become a verified
    account email - ``email_verified`` only rides a genuinely verified entry.
    """
    for entry in emails:
        if entry.get("primary") and entry.get("verified"):
            return entry.get("email"), True
    for entry in emails:
        if entry.get("verified"):
            return entry.get("email"), True
    for entry in emails:
        if entry.get("primary"):
            return entry.get("email"), False
    if emails:
        return emails[0].get("email"), bool(emails[0].get("verified", False))
    return None, False


class GitHubOAuthProvider(AbstractOAuthProvider):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: list[str] | None = None,
    ):
        super().__init__(
            client_id,
            client_secret,
            redirect_uri,
            scopes=scopes or list(GITHUB_DEFAULT_SCOPES),
            authorize_endpoint=GITHUB_AUTHORIZE_ENDPOINT,
            token_endpoint=GITHUB_TOKEN_ENDPOINT,
            userinfo_endpoint=GITHUB_USERINFO_ENDPOINT,
            provider_name=GITHUB,
        )

    async def exchange_code(self, code, code_verifier=None, headers=None):
        merged = {"Accept": "application/json"}
        if headers:
            merged.update(headers)
        return await super().exchange_code(code, code_verifier, merged)

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        profile = await super().get_user_info(access_token)
        httpx = _require_httpx()
        async with httpx.AsyncClient(timeout=OAUTH_HTTP_TIMEOUT_SECONDS) as client:
            resp = await client.get(
                GITHUB_EMAILS_ENDPOINT,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
            if resp.status_code == 200:
                profile["emails"] = resp.json()
        return profile

    async def process_user_info(self, user_info: dict[str, Any]) -> OAuthUserInfo:
        """Normalize GitHub's profile + emails payload.

        Note:
            Raises if ``id`` is missing rather than coercing ``None`` to the
            string ``"None"``. Email is chosen by [_select_github_email][crudauth.oauth.providers.github._select_github_email].
        """
        gh_id = user_info.get("id")
        if gh_id is None:
            raise BadRequestException("GitHub did not return a user id.")
        email, email_verified = _select_github_email(user_info.get("emails", []) or [])
        return OAuthUserInfo(
            provider=GITHUB,
            provider_user_id=str(gh_id),
            email=email,
            email_verified=email_verified,
            name=user_info.get("name"),
            given_name=None,
            family_name=None,
            username=user_info.get("login"),
            picture=user_info.get("avatar_url"),
            raw_data=user_info,
        )
