"""SQLAlchemy rate-limiter backend: lockout and throttle counters shared through your database.

Counters must be shared for a multi-worker lockout to hold: with per-process counters,
N workers give an attacker N times the attempts. This backend keeps them in the
counter table of a [DatabaseStore][crudauth.storage.backends.database.DatabaseStore].
"""

from __future__ import annotations

import math
from typing import Any

from sqlalchemy import BigInteger, and_, case, delete, literal, null, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.dialects import mysql, postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncSession

from ...storage.backends.database import (
    DatabaseStore,
    _rowcount,
    _scalars,
    dialect_of,
    now_ms,
    stored_key,
    upserts_returning,
)
from ...storage.constants import MYSQL_DIALECTS
from ..base import RateLimiterBackend

__all__ = ["DatabaseRateLimiterBackend"]


class DatabaseRateLimiterBackend(RateLimiterBackend):
    """Counters in the counter table of a [DatabaseStore][crudauth.storage.backends.database.DatabaseStore].

    Each increment is one upsert, so concurrent increments are counted exactly. An
    expired counter restarts at the incremented amount with a fresh expiry, in the
    same statement, the way a Redis key that expired would.

    Args:
        database: The store whose counter table holds the counters.
        prefix: Put before every key, so two apps sharing one counter table (an admin
            panel beside the main app) keep separate lockout counters. Empty by default.

    Note:
        - PostgreSQL and SQLite 3.35+: ``INSERT ... ON CONFLICT DO UPDATE ... RETURNING``.
        - MySQL and MariaDB: ``INSERT ... ON DUPLICATE KEY UPDATE``, then the count read back in
          the same transaction while the upsert still holds the row's lock.
        - SQLite before 3.35, which has no ``RETURNING`` (and before 3.24 no upsert):
          an ``UPDATE``, an ``INSERT`` when no row was there, and the count read back,
          all in one transaction that holds SQLite's write lock from the first statement.
    """

    def __init__(self, database: DatabaseStore, prefix: str = ""):
        self.database = database
        self.table = database.counters
        self.prefix = prefix

    def _key(self, key: str) -> str:
        return stored_key(f"{self.prefix}{key}")

    def _expired(self, now: int) -> Any:
        return and_(self.table.c.expires_at.is_not(None), self.table.c.expires_at <= now)

    def _live(self, key: str, now: int) -> Any:
        return and_(
            self.table.c.key == self._key(key),
            or_(self.table.c.expires_at.is_(None), self.table.c.expires_at > now),
        )

    async def _upsert(self, key: str, amount: int, expires_at: Any, new_expiry: int | None) -> int:
        now = now_ms()
        expired = self._expired(now)
        count = case((expired, amount), else_=self.table.c.count + amount)
        expiry = expires_at(expired)
        key = self._key(key)
        start = {"key": key, "count": amount, "expires_at": new_expiry}

        async def increment(session: AsyncSession) -> int:
            dialect = dialect_of(session)
            read_back = select(self.table.c.count).where(self.table.c.key == key)
            if upserts_returning(session):
                insert = postgresql.insert if dialect == "postgresql" else sqlite.insert
                upsert = (
                    insert(self.table)
                    .values(**start)
                    .on_conflict_do_update(
                        index_elements=[self.table.c.key],
                        set_={"count": count, "expires_at": expiry},
                    )
                    .returning(self.table.c.count)
                )
                return int((await _scalars(session, upsert))[0])
            if dialect in MYSQL_DIALECTS:
                statement = mysql.insert(self.table).values(**start)
                await session.execute(
                    statement.on_duplicate_key_update([("count", count), ("expires_at", expiry)])
                )
                return int((await _scalars(session, read_back))[0])
            existing = update(self.table).where(self.table.c.key == key)
            if not await _rowcount(session, existing.values(count=count, expires_at=expiry)):
                await session.execute(self.table.insert().values(**start))
            return int((await _scalars(session, read_back))[0])

        try:
            counted = await self.database.run(increment)
        except IntegrityError:
            counted = await self.database.run(increment)
        await self.database.note_write()
        return counted

    @staticmethod
    def _deadline(expiry: int | None) -> int | None:
        return None if expiry is None else now_ms() + expiry * 1000

    @staticmethod
    def _value(deadline: int | None) -> Any:
        return null() if deadline is None else literal(deadline, BigInteger)

    async def increment(self, key: str, amount: int = 1, expiry: int | None = None) -> int:
        """Increment ``key``; its expiry is set only when the counter starts (or has none)."""
        deadline = self._deadline(expiry)
        armed = self._value(deadline)

        def expires_at(expired: Any) -> Any:
            return case(
                (expired, armed),
                (self.table.c.expires_at.is_(None), armed),
                else_=self.table.c.expires_at,
            )

        return await self._upsert(key, amount, expires_at, deadline)

    async def increment_and_refresh_ttl(
        self, key: str, amount: int = 1, expiry: int | None = None
    ) -> int:
        """Increment ``key`` and push its expiry forward on every call."""
        deadline = self._deadline(expiry)

        def expires_at(expired: Any) -> Any:
            if deadline is not None:
                return self._value(deadline)
            return case((expired, null()), else_=self.table.c.expires_at)

        return await self._upsert(key, amount, expires_at, deadline)

    async def get_count(self, key: str) -> int | None:
        statement = select(self.table.c.count).where(self._live(key, now_ms()))
        rows = await self.database.run(lambda s: _scalars(s, statement), write=False)
        return int(rows[0]) if rows else None

    async def get_ttl(self, key: str) -> int:
        """Seconds left on ``key``, rounded up; ``0`` when it's absent, expired or has no expiry."""
        now = now_ms()
        statement = select(self.table.c.expires_at).where(self._live(key, now))
        rows = await self.database.run(lambda s: _scalars(s, statement), write=False)
        if not rows or rows[0] is None:
            return 0
        return max(0, math.ceil((int(rows[0]) - now) / 1000))

    async def reset(self, key: str) -> None:
        await self.delete(key)

    async def delete(self, key: str) -> bool:
        async def remove(session: AsyncSession) -> int:
            live = await _rowcount(session, delete(self.table).where(self._live(key, now_ms())))
            await session.execute(delete(self.table).where(self.table.c.key == self._key(key)))
            return live

        return bool(await self.database.run(remove))

    async def ping(self) -> bool:
        await self.database.run(lambda s: _scalars(s, select(literal(1))), write=False)
        return True

    async def purge_expired(self) -> int:
        """Delete expired rows from both of the store's tables; see
        [DatabaseStore.purge_expired][crudauth.storage.backends.database.DatabaseStore.purge_expired]."""
        return await self.database.purge_expired()
