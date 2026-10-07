"""SQLAlchemy storage backend: sessions and tokens in your own database.

For deployments that run several workers on PostgreSQL, MySQL or SQLite without
Redis. The memory backend is per-process, so there a login made on one worker is
unknown to the next; this backend shares the same state through two tables.
"""

from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import logging
import math
import random
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, TypeVar

from sqlalchemy import (
    BigInteger,
    Column,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    and_,
    delete,
    func,
    select,
    update,
)
from sqlalchemy.dialects import mysql
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.types import TypeEngine
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ...constants import DEFAULT_SESSION_TTL_SECONDS
from ..base import AbstractSessionStorage, T
from ..constants import (
    DATABASE_KEY_DIGEST_SEPARATOR,
    DATABASE_KEY_MAX_LENGTH,
    DATABASE_MODIFY_MAX_ATTEMPTS,
    DATABASE_PURGE_BATCH_SIZE,
    DATABASE_PURGE_EVERY_WRITES,
    DATABASE_TRANSACTION_ATTEMPTS,
    DEFAULT_COUNTER_TABLE,
    DEFAULT_STORAGE_PREFIX,
    DEFAULT_STORE_TABLE,
)

if TYPE_CHECKING:  # pragma: no cover
    from ...ratelimit.backends.database import DatabaseRateLimiterBackend

__all__ = [
    "DatabaseStore",
    "DatabaseSessionStorage",
    "key_type",
    "dialect_of",
    "now_ms",
    "stored_key",
]

logger = logging.getLogger("crudauth")

R = TypeVar("R")

GLOB_CHARACTERS = "*?["

MYSQL_RETRYABLE_CODES = (1205, 1213)
POSTGRESQL_RETRYABLE_STATES = ("40001", "40P01")


def now_ms() -> int:
    """The application's clock, in epoch milliseconds: every expiry is computed from it."""
    return int(time.time() * 1000)


def _expires_at(seconds: int) -> int:
    return now_ms() + seconds * 1000


def _starts_with(column: Any, prefix: str) -> Any:
    """Case-sensitive on every dialect, unlike ``LIKE`` on SQLite."""
    return func.substr(column, 1, len(prefix)) == prefix


def _retryable(error: DBAPIError) -> bool:
    """A deadlock, lock wait timeout or serialization failure: the transaction rolled back
    whole, so running it again is safe."""
    original = error.orig
    if getattr(original, "sqlstate", None) in POSTGRESQL_RETRYABLE_STATES:
        return True
    if getattr(original, "pgcode", None) in POSTGRESQL_RETRYABLE_STATES:
        return True
    arguments: tuple[Any, ...] = getattr(original, "args", ())
    return bool(arguments) and arguments[0] in MYSQL_RETRYABLE_CODES


def stored_key(key: str) -> str:
    """``key`` as it fits the key column: unchanged up to the column's width, else shortened.

    A longer key keeps its start, so prefix filters still find it, and ends in a SHA-256
    of the whole key, so two long keys sharing a start stay apart. Lockout keys carry the
    identifier as typed, which nothing bounds.
    """
    if len(key) <= DATABASE_KEY_MAX_LENGTH:
        return key
    digest = hashlib.sha256(key.encode()).hexdigest()
    keep = DATABASE_KEY_MAX_LENGTH - len(digest) - len(DATABASE_KEY_DIGEST_SEPARATOR)
    return f"{key[:keep]}{DATABASE_KEY_DIGEST_SEPARATOR}{digest}"


def key_type() -> TypeEngine[str]:
    """The key columns' type: a ``VARCHAR`` compared exactly on every dialect.

    MySQL's and MariaDB's default collations ignore case, and their ``PAD SPACE`` ones
    (``utf8mb4_bin`` included) ignore trailing spaces, so ``"AbC "`` would find
    ``"abc"``. There the columns take a binary collation without padding:
    ``utf8mb4_0900_bin`` on MySQL 8.0.17+ and ``utf8mb4_nopad_bin`` on MariaDB 10.2+.
    Plain SQLAlchemy types, so an Alembic migration renders them with no extra import.
    """
    exact = {"mysql": "utf8mb4_0900_bin", "mariadb": "utf8mb4_nopad_bin"}
    column: TypeEngine[str] = String(DATABASE_KEY_MAX_LENGTH)
    for dialect, collation in exact.items():
        variant = mysql.VARCHAR(DATABASE_KEY_MAX_LENGTH, charset="utf8mb4", collation=collation)
        column = column.with_variant(variant, dialect)
    return column


class DatabaseStore:
    """The tables and the connection a database-backed CRUDAuth keeps its state in.

    One object, handed to ``CRUDAuth(database_store=...)``, puts every server-side
    store on the database: sessions, CSRF tokens, one-time tokens, OAuth state, the
    MFA store, and the rate limiter behind login lockout. Its parts are usable on
    their own too: [storage][crudauth.storage.backends.database.DatabaseStore.storage]
    and [rate_limiter][crudauth.storage.backends.database.DatabaseStore.rate_limiter].

    Args:
        sessions: An ``async_sessionmaker`` (or an ``AsyncEngine``, wrapped in one).
            Every operation opens its own short-lived session from it and closes it
            before returning, so no connection is held between operations. It can
            point at a different database from the app's.
        metadata: The ``MetaData`` the tables are declared on; a fresh one when
            omitted. Pass your app's to have Alembic autogenerate them with your
            own tables.
        store_table: Name of the table stored values live in.
        counter_table: Name of the table rate-limit counters live in.
        purge_every: After this many writes through any of this store's stores and
            limiter, delete up to as many expired rows from each table: as many as
            those writes could have created, so cleanup keeps up under any load while
            the request that triggers it never pays for an unbounded backlog. ``0``
            turns it off, for apps that call
            [purge_expired][crudauth.storage.backends.database.DatabaseStore.purge_expired]
            on a schedule instead. A purge that fails is logged and doesn't fail the
            write that triggered it.
        purge_batch_size: Rows deleted per statement when purging.

    Example:
        ```python
        from crudauth import CRUDAuth, DatabaseStore

        store = DatabaseStore(async_sessionmaker(engine, expire_on_commit=False))
        auth = CRUDAuth(..., database_store=store)

        @asynccontextmanager
        async def lifespan(app):
            await store.create_tables()   # or ship them in an Alembic migration
            await auth.initialize()
            yield
            await auth.shutdown()
        ```

    Note:
        Expiry is an epoch-milliseconds integer computed from the application's
        clock, never the database's, so SQLite, PostgreSQL and MySQL agree. Keep the
        workers' clocks roughly in sync: a skew of a few seconds moves expiry by as
        much.

        A transaction that fails with a deadlock, a lock wait timeout or a
        serialization failure is run again, up to a few times. On MySQL and MariaDB,
        concurrent inserts into a populated table take gap locks and deadlock now
        and then in ordinary use; each attempt is a fresh transaction, and the one
        that failed rolled back whole.
    """

    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession] | AsyncEngine,
        *,
        metadata: MetaData | None = None,
        store_table: str = DEFAULT_STORE_TABLE,
        counter_table: str = DEFAULT_COUNTER_TABLE,
        purge_every: int = DATABASE_PURGE_EVERY_WRITES,
        purge_batch_size: int = DATABASE_PURGE_BATCH_SIZE,
    ):
        if isinstance(sessions, AsyncEngine):
            sessions = async_sessionmaker(sessions, expire_on_commit=False)
        if store_table == counter_table:
            raise ValueError("store_table and counter_table must differ")
        if purge_every < 0:
            raise ValueError("purge_every must be 0 (off) or a positive number of writes")
        if purge_batch_size < 1:
            raise ValueError("purge_batch_size must be at least 1")
        self.sessions = sessions
        self.metadata = metadata if metadata is not None else MetaData()
        self.purge_every = purge_every
        self.purge_batch_size = purge_batch_size
        self._writes_since_purge = 0
        self.store = Table(
            store_table,
            self.metadata,
            Column("key", key_type(), primary_key=True),
            Column("value", Text, nullable=False),
            Column("user_id", key_type(), nullable=True, index=True),
            Column("version", Integer, nullable=False, default=1),
            Column("expires_at", BigInteger, nullable=False, index=True),
        )
        self.counters = Table(
            counter_table,
            self.metadata,
            Column("key", key_type(), primary_key=True),
            Column("count", BigInteger, nullable=False),
            Column("expires_at", BigInteger, nullable=True, index=True),
        )

    def storage(
        self, prefix: str = DEFAULT_STORAGE_PREFIX, expiration: int = DEFAULT_SESSION_TTL_SECONDS
    ) -> "DatabaseSessionStorage[Any]":
        """A store of values under ``prefix``, in the store table."""
        return DatabaseSessionStorage(self, prefix=prefix, expiration=expiration)

    def rate_limiter(self, prefix: str = "") -> "DatabaseRateLimiterBackend":
        """The rate-limit and lockout counters, in the counter table, each key under ``prefix``."""
        from ...ratelimit.backends.database import DatabaseRateLimiterBackend

        return DatabaseRateLimiterBackend(self, prefix=prefix)

    async def create_tables(self) -> None:
        """Create both tables if they don't exist.

        A convenience for development and tests; in production, create them in a
        migration (see the sessions guide for an Alembic snippet).
        """
        async with self.sessions() as session:
            connection = await session.connection()
            await connection.run_sync(
                lambda sync: self.metadata.create_all(sync, tables=[self.store, self.counters])
            )
            await session.commit()

    async def purge_expired(self, batch_size: int | None = None) -> int:
        """Delete every expired row from both tables, ``batch_size`` rows per statement.

        Returns:
            How many rows were deleted.
        """
        size = batch_size or self.purge_batch_size
        deleted = await self._purge(self.store, self.store.c.expires_at, size)
        counters = self.counters.c.expires_at
        return deleted + await self._purge(self.counters, counters, size)

    async def note_write(self) -> None:
        """Count a write, and every ``purge_every`` writes delete up to that many expired rows per table.

        No table gains more rows than writes were counted, so this keeps up, while the
        request that triggers it never works off an unbounded backlog. A failure is logged
        rather than raised, since the write already committed.
        """
        if not self.purge_every:
            return
        self._writes_since_purge += 1
        if self._writes_since_purge < self.purge_every:
            return
        self._writes_since_purge = 0
        batches = math.ceil(self.purge_every / self.purge_batch_size)
        try:
            await self._purge(self.store, self.store.c.expires_at, self.purge_batch_size, batches)
            counters = self.counters.c.expires_at
            await self._purge(self.counters, counters, self.purge_batch_size, batches)
        except Exception as error:
            logger.warning(
                "crudauth: purging expired rows failed (%s); the write itself was saved",
                type(error).__name__,
            )

    async def _purge(
        self, table: Table, expires_at: Any, batch_size: int, max_batches: int | None = None
    ) -> int:
        deleted = 0
        batches = 0
        while max_batches is None or batches < max_batches:
            batches += 1
            expired = select(table.c.key).where(expires_at.is_not(None), expires_at <= now_ms())
            batch = await self.run(lambda s: _scalars(s, expired.limit(batch_size)), write=False)
            if not batch:
                return deleted
            deleted += await self.run(
                lambda s: _rowcount(
                    s,
                    delete(table).where(
                        table.c.key.in_(batch), expires_at.is_not(None), expires_at <= now_ms()
                    ),
                )
            )
            if len(batch) < batch_size:
                return deleted
        return deleted

    async def run(self, work: Callable[[AsyncSession], Awaitable[R]], *, write: bool = True) -> R:
        """Run ``work`` in a session of its own, committing it when ``write``, and again
        when the database rolled it back over a deadlock (see the class's note)."""
        for attempt in range(1, DATABASE_TRANSACTION_ATTEMPTS + 1):
            try:
                async with self.sessions() as session:
                    if not write:
                        return await work(session)
                    async with session.begin():
                        return await work(session)
            except DBAPIError as error:
                if isinstance(error, IntegrityError) or not _retryable(error):
                    raise
                if attempt == DATABASE_TRANSACTION_ATTEMPTS:
                    raise
                await asyncio.sleep(random.uniform(0, 0.01 * 2**attempt))
        raise AssertionError("unreachable")


def dialect_of(session: AsyncSession) -> str:
    """The SQL dialect a session talks to: ``"postgresql"``, ``"mysql"``, ``"sqlite"``, ..."""
    return str(session.get_bind().dialect.name)


def deletes_returning(session: AsyncSession) -> bool:
    """Whether the database takes ``DELETE ... RETURNING``: PostgreSQL, MariaDB, and SQLite 3.35+."""
    return bool(session.get_bind().dialect.delete_returning)


def upserts_returning(session: AsyncSession) -> bool:
    """Whether ``INSERT ... ON CONFLICT DO UPDATE ... RETURNING`` is available: PostgreSQL, and
    SQLite 3.35+ (older SQLite has no ``RETURNING``, and before 3.24 no ``ON CONFLICT`` either)."""
    dialect = session.get_bind().dialect
    return dialect.name in ("postgresql", "sqlite") and bool(dialect.insert_returning)


async def _scalars(session: AsyncSession, statement: Any) -> list[Any]:
    return list((await session.execute(statement)).scalars().all())


async def _rowcount(session: AsyncSession, statement: Any) -> int:
    result: Any = await session.execute(statement)
    return int(result.rowcount or 0)


class DatabaseSessionStorage(AbstractSessionStorage[T]):
    """Values in the store table of a [DatabaseStore][crudauth.storage.backends.database.DatabaseStore].

    Every store shares that table, kept apart by key prefix, the way the Redis
    backend shares one database. An expired row reads as absent everywhere and
    stays until a purge removes it.

    Note:
        - ``modify`` is a compare-and-set on a version column: the update applies
          only to the version it read, and a lost race reads again and reapplies.
        - ``set_if_absent`` removes an expired row and inserts in one transaction;
          a duplicate-key error means another writer won. On SQLite the insert is
          ``INSERT OR IGNORE`` and inserting nothing means the same, so a lost claim
          raises nothing in the driver.
        - ``get_and_delete`` is one ``DELETE ... RETURNING`` where the database has it.
          Elsewhere (MySQL, SQLite before 3.35) it reads the value, then deletes the row
          only if it still holds that value, and hands the value out only if its delete
          removed the row. Concurrent consumers get it exactly once either way.
        - The per-user index is the ``user_id`` column, so it can't drift from the
          rows it describes.
    """

    def __init__(
        self,
        database: DatabaseStore,
        prefix: str = DEFAULT_STORAGE_PREFIX,
        expiration: int = DEFAULT_SESSION_TTL_SECONDS,
        **_: Any,
    ):
        super().__init__(prefix=prefix, expiration=expiration)
        self.database = database
        self.table = database.store

    def _ttl(self, expiration: int | None) -> int:
        return expiration if expiration is not None else self.expiration

    def _live(self, key: str) -> Any:
        return and_(self.table.c.key == key, self.table.c.expires_at > now_ms())

    def _in_prefix(self) -> Any:
        return _starts_with(self.table.c.key, self.prefix)

    def get_key(self, session_id: str) -> str:
        return stored_key(super().get_key(session_id))

    @staticmethod
    def _user_id(data: Any) -> str | None:
        user_id = getattr(data, "user_id", None)
        return None if user_id is None else str(user_id)

    async def create(
        self, data: T, session_id: str | None = None, expiration: int | None = None
    ) -> str:
        sid = session_id or self.generate_session_id()
        key = self.get_key(sid)
        row = {
            "value": data.model_dump_json(),
            "user_id": self._user_id(data),
            "expires_at": _expires_at(self._ttl(expiration)),
        }

        async def write(session: AsyncSession) -> None:
            replaced = await _rowcount(
                session,
                update(self.table)
                .where(self.table.c.key == key)
                .values(**row, version=self.table.c.version + 1),
            )
            if not replaced:
                await session.execute(self.table.insert().values(key=key, version=1, **row))

        try:
            await self.database.run(write)
        except IntegrityError:
            await self.database.run(write)
        await self.database.note_write()
        return sid

    async def get(self, session_id: str, model_class: type[T]) -> T | None:
        statement = select(self.table.c.value).where(self._live(self.get_key(session_id)))
        rows = await self.database.run(lambda s: _scalars(s, statement), write=False)
        return model_class.model_validate_json(rows[0]) if rows else None

    async def update(
        self,
        session_id: str,
        data: T,
        reset_expiration: bool = True,
        expiration: int | None = None,
    ) -> bool:
        values: dict[str, Any] = {
            "value": data.model_dump_json(),
            "user_id": self._user_id(data),
            "version": self.table.c.version + 1,
        }
        if reset_expiration:
            values["expires_at"] = _expires_at(self._ttl(expiration))
        statement = update(self.table).where(self._live(self.get_key(session_id))).values(**values)
        return bool(await self.database.run(lambda s: _rowcount(s, statement)))

    async def modify(
        self,
        session_id: str,
        model_class: type[T],
        change: Callable[[T], None],
        reset_expiration: bool = True,
        expiration: int | None = None,
    ) -> T | None:
        """Compare-and-set on the row's version, retried when another writer got there first.

        Raises:
            RuntimeError: The value kept changing under every attempt, which means a
                writer is updating it in a tight loop.
        """
        key = self.get_key(session_id)
        current = select(self.table.c.value, self.table.c.version).where(self._live(key))
        for _ in range(DATABASE_MODIFY_MAX_ATTEMPTS):
            rows = await self.database.run(lambda s: _all(s, current), write=False)
            if not rows:
                return None
            raw, version = rows[0]
            data = model_class.model_validate_json(raw)
            change(data)
            values: dict[str, Any] = {
                "value": data.model_dump_json(),
                "user_id": self._user_id(data),
                "version": version + 1,
            }
            if reset_expiration:
                values["expires_at"] = _expires_at(self._ttl(expiration))
            guarded = (
                update(self.table)
                .where(self._live(key), self.table.c.version == version)
                .values(**values)
            )
            if await self.database.run(lambda s: _rowcount(s, guarded)):
                return data
        raise RuntimeError(f"Could not update {key!r}: it changed under every attempt")

    async def delete(self, session_id: str, user_id: Any = None) -> bool:
        key = self.get_key(session_id)

        async def remove(session: AsyncSession) -> int:
            live = await _rowcount(session, delete(self.table).where(self._live(key)))
            await session.execute(delete(self.table).where(self.table.c.key == key))
            return live

        return bool(await self.database.run(remove))

    async def extend(self, session_id: str, expiration: int | None = None) -> bool:
        statement = (
            update(self.table)
            .where(self._live(self.get_key(session_id)))
            .values(expires_at=_expires_at(self._ttl(expiration)))
        )
        return bool(await self.database.run(lambda s: _rowcount(s, statement)))

    async def exists(self, session_id: str) -> bool:
        statement = select(self.table.c.key).where(self._live(self.get_key(session_id)))
        return bool(await self.database.run(lambda s: _scalars(s, statement), write=False))

    async def set_if_absent(self, session_id: str, data: T, expiration: int | None = None) -> bool:
        """Insert unless a live row holds the key; an expired one is replaced."""
        key = self.get_key(session_id)
        row = {
            "key": key,
            "value": data.model_dump_json(),
            "user_id": self._user_id(data),
            "version": 1,
            "expires_at": _expires_at(self._ttl(expiration)),
        }

        insert = self.table.insert().prefix_with("OR IGNORE", dialect="sqlite").values(**row)

        async def claim(session: AsyncSession) -> bool:
            await session.execute(
                delete(self.table).where(
                    self.table.c.key == key, self.table.c.expires_at <= now_ms()
                )
            )
            return bool(await _rowcount(session, insert))

        try:
            claimed = await self.database.run(claim)
        except IntegrityError:
            return False
        if claimed:
            await self.database.note_write()
        return claimed

    async def get_and_delete(self, session_id: str, model_class: type[T]) -> T | None:
        """Read and delete; only the caller whose delete removed the row gets the value."""
        key = self.get_key(session_id)

        async def consume(session: AsyncSession) -> str | None:
            if deletes_returning(session):
                returned = delete(self.table).where(self._live(key)).returning(self.table.c.value)
                rows = await _scalars(session, returned)
                return str(rows[0]) if rows else None
            rows = await _scalars(session, select(self.table.c.value).where(self._live(key)))
            if not rows:
                return None
            claimed = delete(self.table).where(self._live(key), self.table.c.value == rows[0])
            return str(rows[0]) if await _rowcount(session, claimed) else None

        raw = await self.database.run(consume)
        return model_class.model_validate_json(raw) if raw is not None else None

    async def get_user_sessions(self, user_id: Any) -> list[str]:
        statement = select(self.table.c.key).where(
            self.table.c.user_id == str(user_id),
            self.table.c.expires_at > now_ms(),
            self._in_prefix(),
        )
        keys = await self.database.run(lambda s: _scalars(s, statement), write=False)
        return [key[len(self.prefix) :] for key in keys]

    async def scan_keys(self, match: str | None = None) -> list[str]:
        """Live keys in this store, matched by glob like the Redis and memory backends."""
        pattern = match or f"{self.prefix}*"
        literal = _literal_prefix(pattern)
        statement = select(self.table.c.key).where(
            self.table.c.expires_at > now_ms(),
            _starts_with(self.table.c.key, literal),
        )
        keys = await self.database.run(lambda s: _scalars(s, statement), write=False)
        return [key for key in keys if fnmatch.fnmatchcase(key, pattern)]

    async def delete_pattern(self, pattern: str) -> int:
        """Delete every key that starts with ``pattern`` (globs in it are honoured)."""
        literal = _literal_prefix(pattern)
        starts = _starts_with(self.table.c.key, literal)
        if literal == pattern:
            return await self.database.run(lambda s: _rowcount(s, delete(self.table).where(starts)))
        candidates = select(self.table.c.key).where(starts)
        keys = [
            key
            for key in await self.database.run(lambda s: _scalars(s, candidates), write=False)
            if fnmatch.fnmatchcase(key, f"{pattern}*")
        ]
        if not keys:
            return 0
        return await self.database.run(
            lambda s: _rowcount(s, delete(self.table).where(self.table.c.key.in_(keys)))
        )

    async def purge_expired(self) -> int:
        """Delete expired rows from both of the store's tables; see
        [DatabaseStore.purge_expired][crudauth.storage.backends.database.DatabaseStore.purge_expired]."""
        return await self.database.purge_expired()


async def _all(session: AsyncSession, statement: Any) -> list[Any]:
    return list((await session.execute(statement)).all())


def _literal_prefix(pattern: str) -> str:
    """The part of a glob before its first wildcard."""
    for index, character in enumerate(pattern):
        if character in GLOB_CHARACTERS:
            return pattern[:index]
    return pattern
