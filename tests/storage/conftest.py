"""Real databases for the storage tests: PostgreSQL, MySQL and MariaDB in testcontainers.

They skip without Docker; SQLite needs nothing. ``sqlite-legacy`` is SQLite told it has
no ``RETURNING``, as before 3.35, and refusing any statement that uses ``RETURNING`` or
``ON CONFLICT`` (absent before 3.24), so the paths for older SQLite run everywhere.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

os.environ.setdefault("TESTCONTAINERS_RYUK_DISABLED", "true")

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import event  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine  # noqa: E402

from crudauth.storage.backends.database import DatabaseStore  # noqa: E402

DIALECTS = ["sqlite", "sqlite-legacy", "postgresql", "mysql", "mariadb"]
LEGACY_SQLITE_SYNTAX = ("RETURNING", "ON CONFLICT")

try:
    from testcontainers.core.docker_client import DockerClient  # type: ignore[import-untyped]
    from testcontainers.mysql import MySqlContainer  # type: ignore[import-untyped]
    from testcontainers.postgres import PostgresContainer  # type: ignore[import-untyped]

    _HAS_TESTCONTAINERS = True
except ImportError:  # pragma: no cover
    _HAS_TESTCONTAINERS = False


def _docker_running() -> bool:
    if not _HAS_TESTCONTAINERS:
        return False
    try:
        DockerClient().client.ping()
    except Exception:
        return False
    return True


@pytest.fixture(scope="session")
def postgresql_url() -> Iterator[str]:
    if not _docker_running():
        pytest.skip("Docker + testcontainers required for PostgreSQL")
    with PostgresContainer("postgres:16-alpine", driver="asyncpg") as container:
        yield container.get_connection_url()


@pytest.fixture(scope="session")
def mysql_url() -> Iterator[str]:
    if not _docker_running():
        pytest.skip("Docker + testcontainers required for MySQL")
    with MySqlContainer("mysql:8.0", dialect="pymysql") as container:
        yield container.get_connection_url().replace("mysql+pymysql://", "mysql+aiomysql://", 1)


@pytest.fixture(scope="session")
def mariadb_url() -> Iterator[str]:
    if not _docker_running():
        pytest.skip("Docker + testcontainers required for MariaDB")
    with MySqlContainer("mariadb:11.4", dialect="pymysql") as container:
        yield container.get_connection_url().replace("mysql+pymysql://", "mariadb+aiomysql://", 1)


def _url(dialect: str, request: pytest.FixtureRequest, tmp_path: Path) -> str:
    if dialect.startswith("sqlite"):
        return f"sqlite+aiosqlite:///{tmp_path / 'store.db'}"
    return str(request.getfixturevalue(f"{dialect}_url"))


@pytest_asyncio.fixture
async def engine_for(request: pytest.FixtureRequest, tmp_path: Path) -> AsyncIterator[Any]:
    """Build engines on a dialect, and drop what they created afterwards."""
    engines: list[tuple[AsyncEngine, DatabaseStore]] = []

    async def build(dialect: str, **store_options: Any) -> tuple[AsyncEngine, DatabaseStore]:
        engine = create_async_engine(_url(dialect, request, tmp_path))
        if dialect == "sqlite-legacy":
            _as_legacy_sqlite(engine)
        store = DatabaseStore(async_sessionmaker(engine, expire_on_commit=False), **store_options)
        async with engine.begin() as connection:
            await connection.run_sync(
                lambda sync: store.metadata.drop_all(sync, tables=[store.store, store.counters])
            )
        await store.create_tables()
        engines.append((engine, store))
        return engine, store

    yield build
    for engine, store in engines:
        async with engine.begin() as connection:
            await connection.run_sync(_drop_tables_of(store))
        await engine.dispose()


def _drop_tables_of(store: DatabaseStore) -> Any:
    def drop(sync: Any) -> None:
        store.metadata.drop_all(sync, tables=[store.store, store.counters])

    return drop


def _as_legacy_sqlite(engine: AsyncEngine) -> None:
    dialect = engine.sync_engine.dialect
    dialect.insert_returning = dialect.update_returning = dialect.delete_returning = False

    @event.listens_for(engine.sync_engine, "before_cursor_execute")
    def refuse(conn: Any, cursor: Any, statement: str, *args: Any) -> None:
        used = [syntax for syntax in LEGACY_SQLITE_SYNTAX if syntax in statement.upper()]
        assert not used, f"SQLite before 3.35 can't run {used}: {statement}"
