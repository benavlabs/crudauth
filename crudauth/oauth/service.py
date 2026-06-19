"""Account linking and provisioning for OAuth logins.

Same users table as password auth: an existing user whose email matches the
OAuth email gets the provider id attached rather than a duplicate account.
"""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..exceptions import BadRequestException
from ..provisioning import NewUserContext, NewUserFields, resolve_new_user_fields
from ..repository import UserRepository
from ..utils import canonical_email, make_unusable_password
from .constants import (
    USERNAME_FALLBACK,
    USERNAME_MAX_LENGTH,
    USERNAME_MAX_SUFFIX_ATTEMPTS,
    USERNAME_MIN_LENGTH,
    USERNAME_RANDOM_SUFFIX_BYTES,
)
from .schemas import OAuthUserInfo

__all__ = ["OAuthAccountService"]


def _sanitize_username(raw: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "_", (raw or "").lower()).strip("_")
    if len(value) < USERNAME_MIN_LENGTH:
        value = f"{USERNAME_FALLBACK}_{value}".strip("_")
    return value[:USERNAME_MAX_LENGTH].strip("_") or USERNAME_FALLBACK


class OAuthAccountService:
    def __init__(
        self,
        repo: UserRepository,
        new_user_fields: NewUserFields | None = None,
        new_user_defaults: dict[str, Any] | None = None,
    ):
        self.repo = repo
        self.new_user_fields = new_user_fields
        self.new_user_defaults = new_user_defaults or {}

    async def get_or_create_user(self, info: OAuthUserInfo, db: AsyncSession) -> tuple[Any, bool]:
        """Resolve an OAuth identity to a user; lookup order: provider id → email → create.

        Returns:
            ``(user, created)`` - ``created`` is ``True`` only when a new row was
            inserted (provider-id and email-link hits return the existing user).

        Raises:
            BadRequestException: When an unverified email matches an existing
                account (see the linking Note), or no email is available to
                create an account.

        Note:
            Auto-linking to an *existing* account requires ``info.email_verified``.
            Attaching a provider to an account on an unverified,
            attacker-influenceable email is an account-takeover vector, so an
            unverified email matching an existing account is refused and routed
            to manual linking.

        Note:
            Creating a *new* account is deliberately allowed on an unverified
            email - there is no existing account to hijack - but the row is
            created with ``email_verified=False`` so it is never treated as
            proven. Linking is the asymmetric case precisely because it touches
            an account the OAuth user may not own.
        """
        user = await self.repo.get_by_oauth(db, info.provider, info.provider_user_id)
        if user is not None:
            return user, False

        if info.email:
            existing = await self.repo.get_by_email(db, info.email)
            if existing is not None:
                if not info.email_verified:
                    raise BadRequestException(
                        "An account with this email already exists. "
                        "Sign in with your existing method to link this provider."
                    )
                await self.repo.update(
                    db,
                    existing,
                    {
                        f"{info.provider}_id": info.provider_user_id,
                        "oauth_provider": info.provider,
                        "oauth_updated_at": datetime.now(timezone.utc),
                    },
                )
                return existing, False

        if not info.email:
            raise BadRequestException(
                f"The {info.provider} account did not provide an email address, "
                "which is required to create an account."
            )
        user = await self._create_user(info, db)
        return user, True

    async def _create_user(self, info: OAuthUserInfo, db: AsyncSession) -> Any:
        """Provision a new OAuth-linked user (unusable password, provider id set).

        Note:
            If the insert loses a race against a concurrent signup on the same
            username base, it's retried once with a random suffix; a second
            failure (e.g. a genuine email collision) propagates.
        """
        base = self._username_base(info)
        now = datetime.now(timezone.utc)
        data: dict[str, Any] = {
            "username": await self._unique_username(db, base),
            "email": canonical_email(info.email),
            "hashed_password": make_unusable_password(),
            "email_verified": info.email_verified,
            "oauth_provider": info.provider,
            f"{info.provider}_id": info.provider_user_id,
            "oauth_created_at": now,
            "oauth_updated_at": now,
        }
        data.update(self.new_user_defaults)
        data.update(
            await resolve_new_user_fields(
                self.new_user_fields,
                NewUserContext(
                    email=data["email"],
                    username=data["username"],
                    source="oauth",
                    db=db,
                    register_data=None,
                    oauth=info,
                ),
                self.repo,
            )
        )
        try:
            return await self.repo.create(db, data)
        except IntegrityError:
            await db.rollback()
            data["username"] = self._random_username(base)
            return await self.repo.create(db, data)

    def _username_base(self, info: OAuthUserInfo) -> str:
        candidate_raw = (
            info.username
            or info.given_name
            or info.name
            or (info.email.split("@")[0] if info.email else None)
            or USERNAME_FALLBACK
        )
        return _sanitize_username(candidate_raw)

    def _random_username(self, base: str) -> str:
        suffix = secrets.token_hex(USERNAME_RANDOM_SUFFIX_BYTES)
        trimmed = base[: USERNAME_MAX_LENGTH - len(suffix) - 1]
        return f"{trimmed}_{suffix}"

    async def _unique_username(self, db: AsyncSession, base: str) -> str:
        """Find an available username from ``base``: numbered suffixes then random.

        Note:
            This is best-effort, not a uniqueness guarantee - it races with
            concurrent signups, so the ``IntegrityError`` retry in
            [_create_user][crudauth.oauth.service.OAuthAccountService._create_user] is the real backstop. The suffix loop is bounded
            (then falls back to a random suffix) so it can't spin.
        """
        if not await self.repo.username_exists(db, base):
            return base
        for n in range(1, USERNAME_MAX_SUFFIX_ATTEMPTS):
            trimmed = base[: USERNAME_MAX_LENGTH - len(str(n)) - 1]
            candidate = f"{trimmed}_{n}"
            if not await self.repo.username_exists(db, candidate):
                return candidate
        return self._random_username(base)
