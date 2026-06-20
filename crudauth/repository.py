"""User persistence, decoupled from your concrete model via ``column_map``.

crudauth speaks a small *logical contract* of field names (``id``, ``email``,
``hashed_password``, ...). [UserRepository][crudauth.repository.UserRepository] translates that contract to
the actual attribute names on your model, so you never have to rename your
schema to adopt the library.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from sqlalchemy import UniqueConstraint, select
from sqlalchemy.ext.asyncio import AsyncSession

from .constants import (
    LOGICAL_FIELDS,
    REGISTRATION_ALLOWED_FIELDS,
    REGISTRATION_GATED_FIELDS,
)
from .utils import canonical_email

logger = logging.getLogger("crudauth")

__all__ = [
    "UserRepository",
    "LOGICAL_FIELDS",
    "REGISTRATION_ALLOWED_FIELDS",
    "REGISTRATION_GATED_FIELDS",
]

# Sentinel: a value that could not be coerced to the PK type (so no row matches).
_UNCOERCIBLE = object()


class UserRepository:
    def __init__(
        self,
        model: type[Any],
        column_map: dict[str, str] | None = None,
        register_extra_fields: Iterable[str] | None = None,
        login_fields: Iterable[str] | None = None,
        recovery: str | None = "email",
    ):
        self.model = model
        self.column_map = column_map or {}
        self.register_extra_fields = frozenset(register_extra_fields or ())
        self.login_fields = (
            list(login_fields) if login_fields is not None else ["email", "username"]
        )
        self.recovery = recovery
        self._warned_provisioning_keys: set[str] = set()

    def _recovery_verified_col(self) -> str | None:
        """The column backing the recovery-factor verified flag, or ``None``.

        Email recovery reuses the always-present ``email_verified``; any other
        factor uses ``{factor}_verified``. ``recovery=None`` has no such column.
        """
        if self.recovery is None:
            return None
        return "email_verified" if self.recovery == "email" else f"{self.recovery}_verified"

    # --- contract translation ------------------------------------------------
    def col(self, logical: str) -> str:
        """Resolve a logical field name to the actual model attribute name."""
        return self.column_map.get(logical, logical)

    def has(self, logical: str) -> bool:
        """Whether the model actually has the column for ``logical``."""
        return hasattr(self.model, self.col(logical))

    def is_unique_column(self, logical: str) -> bool:
        """Whether the resolved column for ``logical`` is single-field unique.

        Detects column-level ``unique=True``, a single-column ``UniqueConstraint``,
        and a single-column unique ``Index`` - all through ``column_map`` (the
        resolved column name). Composite uniqueness does NOT count: a multi-column
        unique key doesn't make one field a safe first-match-wins login key, so a
        composite-only field is treated as non-unique (and the construction check
        raises for it).
        """
        actual = self.col(logical)
        table = self.model.__table__
        if actual not in table.columns:
            return False
        column = table.columns[actual]
        if column.unique:
            return True
        name = column.name
        for constraint in table.constraints:
            if (
                isinstance(constraint, UniqueConstraint)
                and len(constraint.columns) == 1
                and name in constraint.columns.keys()
            ):
                return True
        for index in table.indexes:
            if index.unique and len(index.columns) == 1 and name in index.columns.keys():
                return True
        return False

    def get(self, user: Any, logical: str, default: Any = None) -> Any:
        """Read a logical field off ``user``, or ``default`` if the column is absent."""
        return getattr(user, self.col(logical), default)

    def set_field(self, user: Any, logical: str, value: Any) -> None:
        """Set a logical field on ``user`` by its resolved column name."""
        setattr(user, self.col(logical), value)

    def _attr(self, logical: str) -> Any:
        return getattr(self.model, self.col(logical))

    # --- reads ---------------------------------------------------------------
    def _coerce_id(self, user_id: Any) -> Any:
        """Coerce ``user_id`` to the PK's Python type.

        JWT subjects round-trip as strings (``"42"``); the session path carries
        native ints. Coercing here means *both* paths hit the DB with the right
        type - SQLite tolerates ``"42" == 42`` but Postgres/asyncpg does not.
        Returns ``_UNCOERCIBLE`` when conversion is impossible (e.g. ``"abc"``
        against an int PK), so the lookup can short-circuit to ``None``.
        """
        try:
            py_type = self._attr("id").type.python_type
        except (AttributeError, NotImplementedError):
            return user_id
        if isinstance(user_id, py_type):
            return user_id
        try:
            return py_type(user_id)
        except (ValueError, TypeError):
            return _UNCOERCIBLE

    async def get_by_id(self, db: AsyncSession, user_id: Any) -> Any | None:
        """Fetch the user by primary key, or ``None``.

        Args:
            db: Active async session.
            user_id: PK value; coerced to the column's Python type first (so a
                string ``"42"`` from a token matches an int PK on Postgres).

        Returns:
            The user row, or ``None`` if absent or ``user_id`` can't be coerced.
        """
        coerced = self._coerce_id(user_id)
        if coerced is _UNCOERCIBLE:
            return None
        result = await db.execute(select(self.model).where(self._attr("id") == coerced))
        return result.scalar_one_or_none()

    async def get_by_field(self, db: AsyncSession, logical: str, value: Any) -> Any | None:
        """Fetch the user whose ``logical`` field equals ``value``, or ``None``.

        Email is canonicalized before matching (the column is stored canonical);
        every other field matches as-is.
        """
        if logical == "email" and isinstance(value, str):
            value = canonical_email(value)
        result = await db.execute(select(self.model).where(self._attr(logical) == value))
        return result.scalar_one_or_none()

    async def get_by_email(self, db: AsyncSession, email: str) -> Any | None:
        """Fetch the user by (canonicalized) email, or ``None``."""
        return await self.get_by_field(db, "email", email)

    async def get_by_username(self, db: AsyncSession, username: str) -> Any | None:
        """Fetch the user by username, or ``None``."""
        return await self.get_by_field(db, "username", username)

    async def resolve_login(self, db: AsyncSession, identifier: str) -> Any | None:
        """Resolve a login identifier against ``login_fields``, in order; first match wins.

        Replaces the old ``@``-heuristic: the contract decides which fields a login
        identifier may match. Safe because every login field is asserted unique at
        construction, so a match is unambiguous.
        """
        for logical in self.login_fields:
            user = await self.get_by_field(db, logical, identifier)
            if user is not None:
                return user
        return None

    async def get_by_oauth(
        self, db: AsyncSession, provider: str, provider_user_id: str
    ) -> Any | None:
        """Look up by ``{provider}_id``.

        Note:
            Assumes ``provider`` is a validated/registered provider name (the
            OAuth router checks it before this is reached) - it builds an
            attribute name from the argument, so an unvalidated value would
            probe arbitrary columns (it returns ``None`` for any column the
            model lacks, so the blast radius is a missed lookup, not a leak).
        """
        field = f"{provider}_id"
        if not self.has(field):
            return None
        result = await db.execute(select(self.model).where(self._attr(field) == provider_user_id))
        return result.scalar_one_or_none()

    async def username_exists(self, db: AsyncSession, username: str) -> bool:
        return (await self.get_by_username(db, username)) is not None

    # --- registration gating -------------------------------------------------
    def _gated_names(self) -> set[str]:
        """Gated identifiers: the logical names AND their mapped column names.

        Including the resolved column names closes the alias hole - a
        ``column_map`` that renames ``is_superuser`` to ``is_admin`` plus a
        register schema declaring ``is_admin`` would otherwise slip a gated
        field past a logical-only gate.

        The recovery-factor verified column (e.g. ``phone_verified``) is gated
        too - it must be as unsettable at signup as ``email_verified`` always was,
        since "verified" may only be set by returning the delivered token.
        """
        gated = set(REGISTRATION_GATED_FIELDS) | {self.col(g) for g in REGISTRATION_GATED_FIELDS}
        rv = self._recovery_verified_col()
        if rv is not None:
            gated.add(rv)
        return gated

    def _allowed_register_names(self) -> set[str]:
        """Names registration may keep: the base allowlist plus opted-in extras,
        by both logical and mapped column name."""
        allowed = set(REGISTRATION_ALLOWED_FIELDS) | set(self.register_extra_fields)
        return allowed | {self.col(a) for a in allowed}

    def gated_register_fields(self, schema_fields: Iterable[str]) -> set[str]:
        """Which of ``schema_fields`` are crudauth privileged fields (always dropped)."""
        gated = self._gated_names()
        return {f for f in schema_fields if f in gated}

    def droppable_register_fields(self, schema_fields: Iterable[str]) -> set[str]:
        """Which of ``schema_fields`` map to a real model column but are *not*
        privileged and *not* opted in, so registration silently drops them.

        These are the fields a developer most likely expects to persist (e.g. a
        ``full_name`` column they added to ``register_schema``) and won't, until
        they add the name to ``register_extra_fields``.
        """
        allowed = self._allowed_register_names()
        gated = self._gated_names()
        return {
            f
            for f in schema_fields
            if f not in allowed and f not in gated and hasattr(self.model, self.col(f))
        }

    def filter_registration_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Keep only the allowlisted registration fields; drop everything else.

        A field survives only if it is in :data:`REGISTRATION_ALLOWED_FIELDS` or
        was opted in via ``register_extra_fields`` (matched by logical *or* mapped
        column name) - and is never one of crudauth's privileged logical fields
        (``is_superuser``, ``email_verified``, ``hashed_password``, the oauth
        linkage, the PK), which stay gated even if mistakenly opted in. Unknown
        app columns (``role``, ``credits``, ...) are dropped unless explicitly
        opted in, so a custom ``register_schema`` can't turn ``/register`` into a
        privilege-escalation or mass-assignment endpoint.
        """
        allowed = self._allowed_register_names()
        gated = self._gated_names()
        return {k: v for k, v in data.items() if k in allowed and k not in gated}

    def _contract_names(self) -> set[str]:
        """Every crudauth logical field, by logical AND mapped column name, plus the
        recovery-factor verified column (so a ``new_user_fields`` callback can't set
        ``{factor}_verified`` any more than it can set ``email_verified``)."""
        names = set(LOGICAL_FIELDS) | {self.col(f) for f in LOGICAL_FIELDS}
        rv = self._recovery_verified_col()
        if rv is not None:
            names.add(rv)
        return names

    def filter_provisioning_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Keep only app columns from a ``new_user_fields`` callback.

        Drops any key that is a crudauth logical field (by logical *or* mapped
        column name) and logs a warning, so the callback can fill the app's own
        columns at signup but can never override identity, privilege, or state
        crudauth owns (``email``, ``hashed_password``, ``is_superuser``,
        ``email_verified``, the oauth linkage, the PK). The dropped key keeps
        crudauth's authoritative value.

        Note:
            The callback runs per signup, so a misconfigured one would drop the
            same key on every registration. Each distinct dropped field is warned
            only ONCE per process (deduped across the constant ``new_user_defaults``
            and the runtime callback) so a standing misconfiguration can't flood
            the logs.
        """
        contract = self._contract_names()
        kept = {k: v for k, v in data.items() if k not in contract}
        new_drops = sorted(
            k for k in data if k in contract and k not in self._warned_provisioning_keys
        )
        if new_drops:
            self._warned_provisioning_keys.update(new_drops)
            logger.warning(
                "crudauth: new_user_fields tried to set crudauth-owned field(s) %s; "
                "dropped (crudauth's value is authoritative). Return only app columns.",
                new_drops,
            )
        return kept

    # --- writes --------------------------------------------------------------
    async def create(self, db: AsyncSession, data: dict[str, Any]) -> Any:
        """Insert a user from logical-field ``data`` and return the row.

        Note:
            Owns the transaction boundary - commits and refreshes on the passed-in
            session. Apps using a request-scoped "commit at the end" pattern
            should know auth writes commit eagerly.

        Note:
            Email is canonicalized off the *resolved* column: ``kwargs`` is keyed
            by actual column names, so a ``column_map`` that renames ``email``
            would otherwise be stored un-normalized.
        """
        kwargs: dict[str, Any] = {}
        for logical, value in data.items():
            actual = self.col(logical)
            if hasattr(self.model, actual):
                kwargs[actual] = value
        email_col = self.col("email")
        if email_col in kwargs and isinstance(kwargs[email_col], str):
            kwargs[email_col] = canonical_email(kwargs[email_col])
        user = self.model(**kwargs)
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user

    async def update(self, db: AsyncSession, user: Any, data: dict[str, Any]) -> Any:
        """Apply logical-field ``data`` to ``user`` and return it.

        Note:
            Commits and refreshes eagerly on the passed-in session (see
            [create][crudauth.repository.UserRepository.create]).
        """
        for logical, value in data.items():
            if logical == "email" and isinstance(value, str):
                value = canonical_email(value)
            if self.has(logical):
                self.set_field(user, logical, value)
        await db.commit()
        await db.refresh(user)
        return user

    # --- principal flags -----------------------------------------------------
    def is_superuser(self, user: Any) -> bool:
        return bool(self.get(user, "is_superuser", False))

    def email_verified(self, user: Any) -> bool:
        return bool(self.get(user, "email_verified", False))

    def recovery_verified(self, user: Any) -> bool:
        """Whether the contract's recovery factor is proven controlled.

        Email recovery reads ``email_verified``; another factor reads
        ``{factor}_verified``; ``recovery=None`` is never verified. This is the
        general meaning of "verified" - email is the special case, not the concept.
        """
        col = self._recovery_verified_col()
        if col is None or not self.has(col):
            return False
        return bool(self.get(user, col, False))

    async def mark_recovery_verified(self, db: AsyncSession, user: Any) -> None:
        """Set the contract's recovery-factor verified flag (the verify-flow write)."""
        col = self._recovery_verified_col()
        if col is None:
            return
        await self.update(db, user, {col: True})

    def is_active(self, user: Any) -> bool:
        if not self.has("is_active"):
            return True
        return bool(self.get(user, "is_active", True))

    def user_id(self, user: Any) -> Any:
        return self.get(user, "id")

    def token_version(self, user: Any) -> int:
        """The user's credential epoch (``0`` if the model has no such column)."""
        return int(self.get(user, "token_version", 0) or 0)

    async def increment_token_version(self, db: AsyncSession, user: Any) -> None:
        """Bump the credential epoch, revoking outstanding bearer tokens.

        A no-op when the model has no ``token_version`` column (bearer tokens
        then simply aren't epoch-revocable; the limitation is documented).
        """
        if not self.has("token_version"):
            return
        await self.update(db, user, {"token_version": self.token_version(user) + 1})

    def to_dict(self, user: Any) -> dict[str, Any]:
        """Project a user row onto the logical contract (for hooks).

        Note:
            Contract-only by design - the dict holds the crudauth logical fields
            (``id``, ``email``, ...), not your app's own columns. A hook that
            needs ``full_name`` should re-load the row via ``db`` using the
            ``id``, not expect it in this dict.
        """
        return {f: self.get(user, f) for f in LOGICAL_FIELDS if self.has(f)}
