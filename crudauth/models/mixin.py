"""The auth user-model columns, emitted by [make_auth_identity]
[crudauth.models.mixin.make_auth_identity].

Inherit [AuthUserMixin][crudauth.models.mixin.AuthUserMixin] (the default output)
and get every column crudauth needs. Your own columns coexist freely. For a
different account shape (username-only login, phone recovery, no recovery at all)
call the factory yourself. If you have an existing table with different column
names, don't rename your schema - map the contract via ``column_map=`` on
[CRUDAuth][crudauth.crud_auth.CRUDAuth] instead.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

__all__ = ["AuthUserMixin", "make_auth_identity"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def make_auth_identity(
    *,
    identifiers: Iterable[str] = ("email", "username"),
    recovery: str | None = "email",
    oauth: bool = True,
) -> type[Any]:
    """Build a declarative mixin carrying crudauth's user columns for one account shape.

    The model is the source of truth for shape: this emits the columns, and
    [CRUDAuth][crudauth.crud_auth.CRUDAuth] reads them back at construction, so the
    two can't disagree. ``username``, ``hashed_password``, the status flags,
    ``token_version``, and the timestamps are always emitted; ``email`` and the
    oauth-linkage columns are conditional.

    Args:
        identifiers: Logical fields a user may log in with. Each becomes a
            ``NOT NULL`` unique column. ``email`` here makes the email column
            required.
        recovery: The single field recovery (verify/reset) is delivered against,
            or ``None`` for an account shape with no recovery. ``"email"`` (and not
            an identifier) makes the email column nullable but unique. A non-email
            factor emits a ``{factor}_verified`` bookkeeping flag (e.g.
            ``phone_verified``); you still declare the factor column itself (e.g.
            ``phone``) with your own constraints, the same way you would any column.
        oauth: Emit the oauth-linkage columns (``oauth_provider`` / ``google_id`` /
            ``github_id`` / timestamps). Required for OAuth login.

    Returns:
        A declarative mixin class. Inherit it on your model alongside ``Base``.

    Example:
        ```python
        # the default - email + username login, email recovery (today's shape)
        class User(Base, AuthUserMixin):
            __tablename__ = "users"

        # username-only login, phone recovery
        Identity = make_auth_identity(identifiers=["username"], recovery="phone")
        class User(Base, Identity):
            __tablename__ = "users"
            phone: Mapped[str | None] = mapped_column(unique=True, default=None)
        ```
    """
    ns: dict[str, Any] = {}
    ann: dict[str, Any] = {}

    def add(name: str, annotation: Any, column: Any) -> None:
        ann[name] = annotation
        ns[name] = column

    identifier_set = set(identifiers)
    email_is_identifier = "email" in identifier_set
    email_is_recovery = recovery == "email"

    add("id", Mapped[int], mapped_column(primary_key=True, autoincrement=True))
    if email_is_identifier:
        add("email", Mapped[str], mapped_column(String(320), unique=True, index=True))
    elif email_is_recovery:
        add(
            "email",
            Mapped[str | None],
            mapped_column(String(320), unique=True, index=True, default=None),
        )
    add("username", Mapped[str], mapped_column(String(64), unique=True, index=True))
    add("hashed_password", Mapped[str], mapped_column(String(255)))

    add("is_active", Mapped[bool], mapped_column(default=True))
    add("is_superuser", Mapped[bool], mapped_column(default=False))
    add("email_verified", Mapped[bool], mapped_column(default=False))
    add("token_version", Mapped[int], mapped_column(default=0))

    if recovery is not None and recovery != "email":
        add(f"{recovery}_verified", Mapped[bool], mapped_column(default=False))

    if oauth:
        add("oauth_provider", Mapped[str | None], mapped_column(String(32), default=None))
        add(
            "google_id",
            Mapped[str | None],
            mapped_column(String(64), unique=True, index=True, default=None),
        )
        add(
            "github_id",
            Mapped[str | None],
            mapped_column(String(64), unique=True, index=True, default=None),
        )
        add(
            "oauth_created_at",
            Mapped[datetime | None],
            mapped_column(DateTime(timezone=True), default=None),
        )
        add(
            "oauth_updated_at",
            Mapped[datetime | None],
            mapped_column(DateTime(timezone=True), default=None),
        )

    add("created_at", Mapped[datetime], mapped_column(DateTime(timezone=True), default=_utcnow))
    add(
        "updated_at",
        Mapped[datetime | None],
        mapped_column(DateTime(timezone=True), default=None, onupdate=_utcnow),
    )

    ns["__annotations__"] = ann
    return type("AuthUserMixin", (), ns)


AuthUserMixin = make_auth_identity()
"""Default identity columns: email + username login, email recovery, oauth enabled.

Inherit this for the standard account shape (it is exactly
``make_auth_identity()``):

```python
class User(Base, AuthUserMixin):
    __tablename__ = "users"
    full_name: Mapped[str | None] = mapped_column(default=None)
```

``token_version`` is a monotonic credential epoch: bearer tokens embed it as the
``ver`` claim and a password reset bumps it, so a reset rejects every outstanding
bearer token.
"""
