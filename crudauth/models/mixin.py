"""The [AuthUserMixin][crudauth.models.mixin.AuthUserMixin] - inherit it and get every column crudauth needs.

Your own columns coexist freely. If you have an existing table with different
column names, don't rename your schema - map the contract via
``column_map=`` on [CRUDAuth][crudauth.crud_auth.CRUDAuth] instead.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

__all__ = ["AuthUserMixin"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuthUserMixin:
    """Declarative mixin supplying the full set of columns crudauth relies on.

    Note:
        ``token_version`` is a monotonic credential epoch: bearer tokens embed it
        as the ``ver`` claim and a password reset bumps it, so a reset rejects
        every outstanding bearer token. See
        [BearerTransport][crudauth.transports.bearer.transport.BearerTransport].

    Example:
        ```python
        class User(Base, AuthUserMixin):
            __tablename__ = "users"
            full_name: Mapped[str | None] = mapped_column(default=None)
        ```
    """

    # --- core identity -------------------------------------------------------
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))

    # --- status flags --------------------------------------------------------
    is_active: Mapped[bool] = mapped_column(default=True)
    is_superuser: Mapped[bool] = mapped_column(default=False)
    email_verified: Mapped[bool] = mapped_column(default=False)

    token_version: Mapped[int] = mapped_column(default=0)

    # --- oauth linkage -------------------------------------------------------
    oauth_provider: Mapped[str | None] = mapped_column(String(32), default=None)
    google_id: Mapped[str | None] = mapped_column(String(64), unique=True, index=True, default=None)
    github_id: Mapped[str | None] = mapped_column(String(64), unique=True, index=True, default=None)
    oauth_created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    oauth_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    # --- timestamps ----------------------------------------------------------
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None, onupdate=_utcnow
    )
