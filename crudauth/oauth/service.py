"""Account linking and provisioning for OAuth logins.

Same users table as password auth: an existing user whose email matches the
OAuth email gets the provider id attached rather than a duplicate account.
"""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..exceptions import OAuthAccountException
from ..mfa.constants import MFA_FIELDS
from ..provisioning import NewUserContext, NewUserFields, resolve_new_user_fields
from ..repository import UserRepository
from ..utils import canonical_email, make_unusable_password
from .constants import (
    ACCOUNT_INACTIVE,
    EMAIL_MISSING,
    EMAIL_TOO_LONG,
    EMAIL_UNVERIFIED,
    PROVIDER_ALREADY_LINKED,
    USERNAME_FALLBACK,
    USERNAME_MAX_LENGTH,
    USERNAME_MAX_SUFFIX_ATTEMPTS,
    USERNAME_MIN_LENGTH,
    USERNAME_RANDOM_SUFFIX_BYTES,
)
from .schemas import OAuthUserInfo

if TYPE_CHECKING:  # pragma: no cover
    from ..transports.session.manager import SessionManager

__all__ = ["OAuthAccountService"]


def _sanitize_username(raw: str, max_length: int) -> str:
    value = re.sub(r"[^a-z0-9]+", "_", (raw or "").lower()).strip("_")
    if len(value) < USERNAME_MIN_LENGTH:
        value = f"{USERNAME_FALLBACK}_{value}".strip("_")
    return value[:max_length].rstrip("_")


class OAuthAccountService:
    """Resolve an OAuth identity to a user, creating or linking as needed.

    The linking rules live here (lookup order: provider id → verified email →
    create), so a hand-written callback reuses them. Reachable as ``auth.oauth``
    (``None`` when OAuth isn't configured). ``session_manager`` is used to sign
    out the sessions of an unverified account that a provider claims.

    Example:
        ```python
        if auth.oauth is not None:
            user, created = await auth.oauth.get_or_create_user(info, db)
        ```
    """

    def __init__(
        self,
        repo: UserRepository,
        new_user_fields: NewUserFields | None = None,
        new_user_defaults: dict[str, Any] | None = None,
        *,
        session_manager: "SessionManager | None" = None,
    ):
        self.repo = repo
        self.new_user_fields = new_user_fields
        self.new_user_defaults = new_user_defaults or {}
        self.session_manager = session_manager
        self._username_max_length = repo.string_length("username") or USERNAME_MAX_LENGTH

    async def get_or_create_user(self, info: OAuthUserInfo, db: AsyncSession) -> tuple[Any, bool]:
        """Resolve an OAuth identity to a user; lookup order: provider id → email → create.

        Returns:
            ``(user, created)`` - ``created`` is ``True`` only when a new row was
            inserted (provider-id and email-link hits return the existing user).

        Raises:
            OAuthAccountException: When the provider gives no email, an
                unverified email, an email longer than the ``email`` column, or
                the matching account is already linked to a different account
                of the same provider, or is inactive. An inactive account is
                refused before anything is written to it: it is neither linked
                nor claimed.

        Note:
            Only a verified provider email links or creates an account. Linking
            to an account whose own email was never verified claims it: its
            password becomes unusable, any two-factor enrollment is removed, its
            ``token_version`` is bumped, its sessions are signed out, and its
            email is marked verified.
        """
        user = await self.repo.get_by_oauth(db, info.provider, info.provider_user_id)
        if user is not None:
            self._refuse_inactive(user)
            return user, False

        if not info.email:
            raise OAuthAccountException(
                EMAIL_MISSING,
                f"The {info.provider} account did not provide an email address, "
                "which is required to sign in.",
            )
        if not info.email_verified:
            raise OAuthAccountException(
                EMAIL_UNVERIFIED,
                f"The {info.provider} account's email address isn't verified. "
                f"Verify it with {info.provider} and try again.",
            )

        existing = await self.repo.get_by_email(db, info.email)
        if existing is not None:
            self._refuse_inactive(existing)
            return await self._link(existing, info, db), False

        limit = self.repo.exceeds_length("email", canonical_email(info.email))
        if limit is not None:
            raise OAuthAccountException(
                EMAIL_TOO_LONG,
                f"The {info.provider} email address is longer than the {limit} characters "
                "this app accepts.",
            )
        return await self._create_user(info, db), True

    def _refuse_inactive(self, user: Any) -> None:
        if not self.repo.is_active(user):
            raise OAuthAccountException(ACCOUNT_INACTIVE, "This account is disabled.")

    async def _link(self, user: Any, info: OAuthUserInfo, db: AsyncSession) -> Any:
        if self.repo.get(user, f"{info.provider}_id") is not None:
            raise OAuthAccountException(
                PROVIDER_ALREADY_LINKED,
                f"This account is already linked to a different {info.provider} account.",
            )
        claimed = not self.repo.email_verified(user)
        data: dict[str, Any] = {
            f"{info.provider}_id": info.provider_user_id,
            "oauth_provider": info.provider,
            "oauth_updated_at": datetime.now(timezone.utc),
        }
        if claimed:
            data["hashed_password"] = make_unusable_password()
            data["email_verified"] = True
            data.update(dict.fromkeys(MFA_FIELDS))
        await self.repo.update(db, user, data)
        if claimed:
            await self.repo.increment_token_version(db, user)
            if self.session_manager is not None:
                await self.session_manager.terminate_all_user_sessions(
                    self.repo.user_id(user), reason="oauth_account_claimed"
                )
        return user

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
            "email_verified": True,
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
        return _sanitize_username(candidate_raw, self._username_max_length)

    def _username_with_suffix(self, base: str, suffix: str) -> str:
        available = self._username_max_length - len(suffix) - 1
        if available <= 0:
            return suffix[: self._username_max_length]
        return f"{base[:available].rstrip('_')}_{suffix}"

    def _random_username(self, base: str) -> str:
        suffix = secrets.token_hex(USERNAME_RANDOM_SUFFIX_BYTES)
        return self._username_with_suffix(base, suffix)

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
            candidate = self._username_with_suffix(base, str(n))
            if not await self.repo.username_exists(db, candidate):
                return candidate
        return self._random_username(base)
