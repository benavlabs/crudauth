"""The database store and rate limiter, held to the same contract as the memory and Redis ones.

The shared contract runs against memory, Redis (fakeredis) and the database backend on
SQLite, PostgreSQL and MySQL. PostgreSQL and MySQL run in testcontainers and skip
without Docker. The database-only tests cover what the other backends get for free:
expiry read from a column, purging, and several workers on one database.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import fakeredis.aioredis  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from pydantic import BaseModel  # noqa: E402
from sqlalchemy import event  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402

from crudauth.ratelimit import MemoryRateLimiterBackend, RedisBackend  # noqa: E402
from crudauth.storage import MemorySessionStorage  # noqa: E402
from crudauth.storage.backends import database as database_module  # noqa: E402
from crudauth.storage.backends.database import DatabaseStore  # noqa: E402
from crudauth.storage.backends.redis import RedisSessionStorage  # noqa: E402
from tests.storage.conftest import DIALECTS  # noqa: E402

CONCURRENCY = 20


class Record(BaseModel):
    user_id: int | None = None
    first: str = ""
    second: str = ""


@pytest_asyncio.fixture(params=["memory", "redis", *DIALECTS])
async def storage(request: pytest.FixtureRequest, engine_for: Any) -> AsyncIterator[Any]:
    kind = request.param
    if kind == "memory":
        yield MemorySessionStorage(prefix="test:")
    elif kind == "redis":
        client = fakeredis.aioredis.FakeRedis()
        yield RedisSessionStorage(prefix="test:", client=client)
        await client.aclose()
    else:
        _, store = await engine_for(kind)
        yield store.storage(prefix="test:")


@pytest_asyncio.fixture(params=["memory", "redis", *DIALECTS])
async def limiter(request: pytest.FixtureRequest, engine_for: Any) -> AsyncIterator[Any]:
    kind = request.param
    if kind == "memory":
        yield MemoryRateLimiterBackend()
    elif kind == "redis":
        client = fakeredis.aioredis.FakeRedis()
        yield RedisBackend(client=client)
        await client.aclose()
    else:
        _, store = await engine_for(kind)
        yield store.rate_limiter()


class TestStoreContract:
    async def test_a_value_round_trips(self, storage: Any) -> None:
        await storage.create(Record(user_id=1, first="a"), session_id="one", expiration=60)

        assert await storage.exists("one")
        assert await storage.get("one", Record) == Record(user_id=1, first="a")

    async def test_update_rewrites_a_live_value_and_refuses_a_missing_one(
        self, storage: Any
    ) -> None:
        await storage.create(Record(first="a"), session_id="one", expiration=60)

        assert await storage.update("one", Record(first="b"))
        assert (await storage.get("one", Record)).first == "b"
        assert await storage.update("missing", Record(first="x")) is False
        assert await storage.get("missing", Record) is None

    async def test_create_over_an_existing_key_replaces_it(self, storage: Any) -> None:
        await storage.create(Record(first="a"), session_id="one", expiration=60)
        await storage.create(Record(first="b"), session_id="one", expiration=60)

        assert (await storage.get("one", Record)).first == "b"

    async def test_delete_reports_whether_it_removed_something(self, storage: Any) -> None:
        await storage.create(Record(user_id=1), session_id="one", expiration=60)

        assert await storage.delete("one") is True
        assert await storage.delete("one") is False
        assert not await storage.exists("one")

    async def test_extend_needs_a_live_value(self, storage: Any) -> None:
        await storage.create(Record(), session_id="one", expiration=60)

        assert await storage.extend("one", 120) is True
        assert await storage.extend("missing", 120) is False

    async def test_concurrent_modifies_of_different_fields_both_land(self, storage: Any) -> None:
        await storage.create(Record(), session_id="one", expiration=60)

        def set_first(record: Record) -> None:
            record.first = "first"

        def set_second(record: Record) -> None:
            record.second = "second"

        await asyncio.gather(
            *[storage.modify("one", Record, set_first) for _ in range(CONCURRENCY // 2)],
            *[storage.modify("one", Record, set_second) for _ in range(CONCURRENCY // 2)],
        )

        assert await storage.get("one", Record) == Record(first="first", second="second")

    async def test_modify_of_a_missing_value_is_none(self, storage: Any) -> None:
        assert await storage.modify("missing", Record, lambda record: None) is None

    async def test_exactly_one_concurrent_set_if_absent_wins(self, storage: Any) -> None:
        won = await asyncio.gather(
            *[storage.set_if_absent("token", Record(first=str(n)), 60) for n in range(CONCURRENCY)]
        )

        assert won.count(True) == 1
        assert await storage.exists("token")

    async def test_get_and_delete_hands_the_value_out_once(self, storage: Any) -> None:
        await storage.create(Record(first="once"), session_id="state", expiration=60)

        taken = await asyncio.gather(
            *[storage.get_and_delete("state", Record) for _ in range(CONCURRENCY)]
        )

        assert [record.first for record in taken if record is not None] == ["once"]
        assert not await storage.exists("state")

    async def test_a_users_sessions_are_listed_and_dropped_with_them(self, storage: Any) -> None:
        await storage.create(Record(user_id=7), session_id="a", expiration=60)
        await storage.create(Record(user_id=7), session_id="b", expiration=60)
        await storage.create(Record(user_id=8), session_id="c", expiration=60)

        assert sorted(await storage.get_user_sessions(7)) == ["a", "b"]
        await storage.delete("a")
        assert await storage.get_user_sessions(7) == ["b"]

    async def test_scan_keys_matches_by_glob(self, storage: Any) -> None:
        await storage.create(Record(), session_id="alpha", expiration=60)
        await storage.create(Record(), session_id="beta", expiration=60)

        assert sorted(await storage.scan_keys("test:*")) == ["test:alpha", "test:beta"]
        assert await storage.scan_keys("test:al*") == ["test:alpha"]


class TestCounterContract:
    async def test_concurrent_increments_are_counted_exactly(self, limiter: Any) -> None:
        await asyncio.gather(*[limiter.increment("hits", 1, 60) for _ in range(CONCURRENCY)])

        assert await limiter.get_count("hits") == CONCURRENCY

    async def test_the_expiry_is_armed_on_first_touch_only(self, limiter: Any) -> None:
        await limiter.increment("window", 1, 60)
        await limiter.increment("window", 1, 600)

        assert 0 < await limiter.get_ttl("window") <= 60

    async def test_refresh_pushes_the_expiry_forward_every_time(self, limiter: Any) -> None:
        await limiter.increment_and_refresh_ttl("rounds", 1, 60)
        count = await limiter.increment_and_refresh_ttl("rounds", 1, 600)

        assert count == 2
        assert 60 < await limiter.get_ttl("rounds") <= 600

    async def test_a_counter_without_an_expiry_gets_one_on_its_next_increment(
        self, limiter: Any
    ) -> None:
        await limiter.increment("bare", 1)
        await limiter.increment("bare", 1, 60)

        assert 0 < await limiter.get_ttl("bare") <= 60

    async def test_delete_and_reset_clear_a_counter(self, limiter: Any) -> None:
        await limiter.increment("gone", 3, 60)

        assert await limiter.delete("gone") is True
        assert await limiter.get_count("gone") is None
        assert await limiter.get_ttl("gone") == 0
        await limiter.increment("gone", 1, 60)
        await limiter.reset("gone")
        assert await limiter.get_count("gone") is None

    async def test_ping(self, limiter: Any) -> None:
        assert await limiter.ping() is True


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Any:
    """The database backend's clock, moved by hand."""

    class Clock:
        now = database_module.now_ms()

        def advance(self, seconds: float) -> None:
            self.now += int(seconds * 1000)

    moved = Clock()
    monkeypatch.setattr(database_module, "now_ms", lambda: moved.now)
    from crudauth.ratelimit.backends import database as limiter_module

    monkeypatch.setattr(limiter_module, "now_ms", lambda: moved.now)
    return moved


@pytest.mark.parametrize("dialect", DIALECTS)
class TestDatabaseOnly:
    async def test_an_expired_value_is_absent_everywhere(
        self, dialect: str, engine_for: Any, clock: Any
    ) -> None:
        _, store = await engine_for(dialect)
        storage = store.storage(prefix="test:")
        await storage.create(Record(user_id=3, first="old"), session_id="one", expiration=10)
        clock.advance(11)

        assert await storage.get("one", Record) is None
        assert not await storage.exists("one")
        assert await storage.get_user_sessions(3) == []
        assert await storage.scan_keys("test:*") == []
        assert await storage.update("one", Record(first="new")) is False
        assert await storage.extend("one", 60) is False
        assert await storage.modify("one", Record, lambda record: None) is None
        assert await storage.get_and_delete("one", Record) is None
        assert await storage.delete("one") is False

    async def test_an_expired_value_does_not_block_set_if_absent(
        self, dialect: str, engine_for: Any, clock: Any
    ) -> None:
        _, store = await engine_for(dialect)
        storage = store.storage(prefix="test:")
        await storage.set_if_absent("token", Record(first="old"), 10)
        clock.advance(11)

        assert await storage.set_if_absent("token", Record(first="new"), 10) is True
        assert (await storage.get("token", Record)).first == "new"

    async def test_an_expired_counter_starts_over_with_a_fresh_expiry(
        self, dialect: str, engine_for: Any, clock: Any
    ) -> None:
        _, store = await engine_for(dialect)
        limiter = store.rate_limiter()
        await limiter.increment("hits", 5, 60)
        clock.advance(61)

        assert await limiter.get_count("hits") is None
        assert await limiter.increment("hits", 1, 60) == 1
        assert await limiter.get_ttl("hits") == 60
        clock.advance(61)
        assert await limiter.increment_and_refresh_ttl("hits", 2, 30) == 2
        assert await limiter.get_ttl("hits") == 30

    async def test_purge_removes_expired_rows_and_keeps_live_ones(
        self, dialect: str, engine_for: Any, clock: Any
    ) -> None:
        _, store = await engine_for(dialect, purge_every=0)
        storage = store.storage(prefix="test:")
        limiter = store.rate_limiter()
        for n in range(7):
            await storage.create(Record(), session_id=f"old{n}", expiration=10)
        await limiter.increment("old", 1, 10)
        await limiter.increment("forever", 1)
        await storage.create(Record(), session_id="live", expiration=600)
        clock.advance(11)

        assert await store.purge_expired(batch_size=3) == 8
        assert await storage.exists("live")
        assert await limiter.get_count("forever") == 1
        assert await store.purge_expired() == 0

    async def test_expired_rows_are_purged_as_writes_go_by(
        self, dialect: str, engine_for: Any, clock: Any
    ) -> None:
        engine, store = await engine_for(dialect, purge_every=3)
        storage = store.storage(prefix="test:")
        await storage.create(Record(), session_id="old", expiration=10)
        clock.advance(11)
        await storage.create(Record(), session_id="a", expiration=600)
        await storage.create(Record(), session_id="b", expiration=600)

        async with engine.connect() as connection:
            keys = sorted((await connection.execute(store.store.select())).scalars().all())
        assert keys == ["test:a", "test:b"]

    async def test_two_workers_on_one_database_share_everything(
        self, dialect: str, engine_for: Any
    ) -> None:
        engine, store = await engine_for(dialect)
        other_worker = DatabaseStore(async_sessionmaker(engine, expire_on_commit=False))

        await store.storage(prefix="s:").create(Record(user_id=1), session_id="sid", expiration=60)
        await store.rate_limiter().increment("login", 1, 60)

        assert await other_worker.storage(prefix="s:").get("sid", Record) == Record(user_id=1)
        assert await other_worker.rate_limiter().increment("login", 1, 60) == 2

    async def test_no_connection_is_held_between_operations(
        self, dialect: str, engine_for: Any
    ) -> None:
        engine, store = await engine_for(dialect)
        storage = store.storage(prefix="test:")
        limiter = store.rate_limiter()

        await storage.create(Record(user_id=1), session_id="one", expiration=60)
        await storage.modify("one", Record, lambda record: None)
        await storage.get_and_delete("one", Record)
        await limiter.increment("hits", 1, 60)
        await limiter.get_ttl("hits")

        assert engine.pool.checkedout() == 0

    async def test_table_names_are_configurable(self, dialect: str, engine_for: Any) -> None:
        engine, store = await engine_for(
            dialect, store_table="admin_auth_store", counter_table="admin_auth_counters"
        )
        await store.storage().create(Record(), session_id="one", expiration=60)

        assert store.store.name == "admin_auth_store"
        async with engine.connect() as connection:
            rows = (await connection.execute(store.store.select())).all()
        assert len(rows) == 1


def test_the_two_tables_must_differ() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    with pytest.raises(ValueError, match="must differ"):
        DatabaseStore(engine, store_table="same", counter_table="same")


def test_purge_every_cannot_be_negative() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    with pytest.raises(ValueError, match="purge_every"):
        DatabaseStore(engine, purge_every=-1)


def test_an_engine_is_wrapped_in_a_sessionmaker() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")

    assert isinstance(DatabaseStore(engine).sessions, async_sessionmaker)


@pytest.mark.parametrize("dialect", DIALECTS)
class TestDatabaseEdges:
    async def test_a_key_past_the_column_width_is_stored_and_found(
        self, dialect: str, engine_for: Any
    ) -> None:
        """Lockout keys carry the identifier as typed, and nothing bounds an email's length."""
        _, store = await engine_for(dialect)
        storage = store.storage(prefix="test:")
        limiter = store.rate_limiter()
        long_id = "x" * 300
        long_key = f"login:pair:203.0.113.9:{'a' * 240}@example.com"

        await storage.create(Record(user_id=1, first="long"), session_id=long_id, expiration=60)
        assert (await storage.get(long_id, Record)).first == "long"
        assert await storage.get("x" * 299, Record) is None
        assert await storage.delete(long_id) is True

        assert await limiter.increment(long_key, 1, 60) == 1
        assert await limiter.increment(long_key, 1, 60) == 2
        assert await limiter.increment(long_key[:-1], 1, 60) == 1
        assert 0 < await limiter.get_ttl(long_key) <= 60
        assert await limiter.delete(long_key) is True

    async def test_keys_differing_in_case_or_a_trailing_space_stay_apart(
        self, dialect: str, engine_for: Any
    ) -> None:
        _, store = await engine_for(dialect)
        storage = store.storage(prefix="test:")
        limiter = store.rate_limiter()

        await storage.create(Record(first="upper"), session_id="AbC", expiration=60)
        await storage.create(Record(first="spaced"), session_id="abc ", expiration=60)

        assert await storage.get("abc", Record) is None
        assert (await storage.get("AbC", Record)).first == "upper"
        assert (await storage.get("abc ", Record)).first == "spaced"
        assert await limiter.increment("Key", 1, 60) == 1
        assert await limiter.increment("key", 1, 60) == 1

    async def test_a_failing_purge_does_not_fail_the_write_it_followed(
        self,
        dialect: str,
        engine_for: Any,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        _, store = await engine_for(dialect, purge_every=1)

        async def broken(*args: Any, **kwargs: Any) -> int:
            raise RuntimeError("deadlock")

        monkeypatch.setattr(store, "_purge", broken)
        storage = store.storage(prefix="test:")

        with caplog.at_level("WARNING", logger="crudauth"):
            await storage.create(Record(), session_id="one", expiration=60)
            assert await storage.set_if_absent("claim", Record(), 60) is True
            assert await store.rate_limiter().increment("hits", 1, 60) == 1

        assert await storage.exists("one")
        assert "purging expired rows failed" in caplog.text

    async def test_a_purge_on_a_write_deletes_as_many_rows_as_writes_were_counted(
        self, dialect: str, engine_for: Any, clock: Any
    ) -> None:
        """Enough to keep up with what the writes created, never the whole backlog at once."""
        engine, store = await engine_for(dialect, purge_every=0, purge_batch_size=2)
        storage = store.storage(prefix="test:")
        for n in range(7):
            await storage.create(Record(), session_id=f"old{n}", expiration=10)
        clock.advance(11)
        store.purge_every = 4

        for n in range(4):
            await storage.create(Record(), session_id=f"new{n}", expiration=600)

        async with engine.connect() as connection:
            remaining = len((await connection.execute(store.store.select())).all())
        assert remaining == 4 + 7 - 4
        assert await store.purge_expired() == 3

    async def test_a_lost_claim_on_sqlite_raises_nothing_in_the_driver(
        self, dialect: str, engine_for: Any
    ) -> None:
        """SQLAlchemy 2.0's aiosqlite adapter leaves the cursor of a failed statement open. On
        Python 3.11, where ``rollback()`` no longer resets statements and a failed one isn't reset
        either, that cursor kept the pooled connection holding SQLite's lock until it was garbage
        collected, and every other writer timed out with "database is locked". Losing a claim is
        the expected outcome, so on SQLite it must not go through a duplicate-key error at all."""
        if not dialect.startswith("sqlite"):
            pytest.skip("aiosqlite only")
        engine, store = await engine_for(dialect, purge_every=0)
        storage = store.storage(prefix="test:")
        errors: list[str] = []

        def record(context: Any) -> None:
            errors.append(type(context.original_exception).__name__)

        event.listen(engine.sync_engine, "handle_error", record)
        won = await storage.set_if_absent("token", Record(first="a"), 60)
        lost = await storage.set_if_absent("token", Record(first="b"), 60)
        event.remove(engine.sync_engine, "handle_error", record)

        assert (won, lost) == (True, False)
        assert errors == []
        assert (await storage.get("token", Record)) == Record(first="a")

    async def test_concurrent_writes_into_a_populated_table_all_succeed(
        self, dialect: str, engine_for: Any
    ) -> None:
        """Rows already in the table give MySQL gaps to lock; a deadlock must be retried, not raised."""
        engine, store = await engine_for(dialect, purge_every=0)
        storage = store.storage(prefix="test:")
        limiter = store.rate_limiter()
        async with engine.begin() as connection:
            await connection.execute(
                store.store.insert(),
                [
                    {"key": f"test:{n:04}", "value": "{}", "version": 1, "expires_at": 2**62}
                    for n in range(0, 400, 2)
                ],
            )
            await connection.execute(
                store.counters.insert(),
                [{"key": f"{n:04}", "count": 1, "expires_at": None} for n in range(0, 400, 2)],
            )

        rounds = {
            "create distinct": [
                storage.create(Record(), session_id=f"{n:04}c", expiration=60) for n in range(300)
            ],
            "set_if_absent distinct": [
                storage.set_if_absent(f"{n:04}s", Record(), 60) for n in range(300)
            ],
            "set_if_absent one key": [
                storage.set_if_absent("0201", Record(first=str(n)), 60) for n in range(300)
            ],
            "create one key": [
                storage.create(Record(first=str(n)), session_id="0203", expiration=60)
                for n in range(300)
            ],
            "increment distinct": [limiter.increment(f"{n:04}i", 1, 60) for n in range(300)],
            "increment one key": [limiter.increment("0205", 1, 60) for _ in range(300)],
        }
        outcomes = {
            name: await asyncio.gather(*calls, return_exceptions=True)
            for name, calls in rounds.items()
        }

        failures = {
            name: [repr(result) for result in results if isinstance(result, BaseException)][:3]
            for name, results in outcomes.items()
        }
        assert not any(failures.values()), failures
        assert outcomes["set_if_absent distinct"] == [True] * 300
        assert outcomes["set_if_absent one key"].count(True) == 1
        assert sorted(
            count for count in outcomes["increment one key"] if isinstance(count, int)
        ) == list(range(1, 301))

    async def test_prefixes_and_globs_match_exactly_whatever_the_characters(
        self, dialect: str, engine_for: Any
    ) -> None:
        _, store = await engine_for(dialect)
        storage = store.storage(prefix="tëst:")
        for session_id in ("a1", "a2", "b1", "A3"):
            await storage.create(Record(user_id=7), session_id=session_id, expiration=60)
        await store.storage(prefix="other:").create(Record(), session_id="a9", expiration=60)

        assert sorted(await storage.scan_keys()) == ["tëst:A3", "tëst:a1", "tëst:a2", "tëst:b1"]
        assert len(await storage.get_user_sessions(7)) == 4
        assert await storage.delete_pattern("tëst:a?") == 2
        assert sorted(await storage.scan_keys()) == ["tëst:A3", "tëst:b1"]
        assert await store.storage(prefix="other:").exists("a9")


def test_alembic_renders_the_tables_with_no_import_of_crudauth() -> None:
    """A migration autogenerated from the tables must run with Alembic's standard imports."""
    alembic = pytest.importorskip("alembic.autogenerate")
    from alembic.migration import MigrationContext
    from sqlalchemy import create_engine

    store = DatabaseStore(create_async_engine("sqlite+aiosqlite://"))
    with create_engine("sqlite://").connect() as connection:
        context = MigrationContext.configure(connection)
        operations = alembic.produce_migrations(context, store.metadata)
        imports: set[str] = set()
        code = alembic.render_python_code(operations.upgrade_ops, imports=imports)

    assert "crudauth.storage" not in code
    assert "utf8mb4_0900_bin" in code and "utf8mb4_nopad_bin" in code
    namespace: dict[str, Any] = {}
    exec("import sqlalchemy as sa\nfrom alembic import op\n" + "\n".join(imports), namespace)
    exec(f"def upgrade():\n{code}", namespace)
