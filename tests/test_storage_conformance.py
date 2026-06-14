"""Every AbstractSessionStorage backend passes the same behavioral suite."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import fakeredis.aioredis
import pytest

from crudauth.storage.backends.memory import MemorySessionStorage
from crudauth.storage.backends.redis import RedisSessionStorage
from crudauth.transports.session.schemas import SessionData


def _fakeredis_client():
    return fakeredis.aioredis.FakeRedis()


@pytest.fixture(params=["memory", "redis"])
async def storage(request) -> AsyncIterator:
    if request.param == "memory":
        yield MemorySessionStorage(prefix="t:", expiration=100)
    else:
        store: RedisSessionStorage[SessionData] = RedisSessionStorage(
            prefix="t:", expiration=100, client=_fakeredis_client()
        )
        yield store
        await store.close()


async def test_create_get_roundtrip(storage) -> None:
    sid = await storage.create(SessionData(user_id=1), session_id="s1")
    assert sid == "s1"
    got = await storage.get("s1", SessionData)
    assert got is not None and got.user_id == 1


async def test_exists_and_delete(storage) -> None:
    await storage.create(SessionData(user_id=1), session_id="s1")
    assert await storage.exists("s1") is True
    assert await storage.delete("s1") is True
    assert await storage.exists("s1") is False
    assert await storage.get("s1", SessionData) is None


async def test_update(storage) -> None:
    await storage.create(SessionData(user_id=1), session_id="s1")
    data = await storage.get("s1", SessionData)
    data.metadata["x"] = "y"
    assert await storage.update("s1", data) is True
    again = await storage.get("s1", SessionData)
    assert again.metadata["x"] == "y"
    # update on a missing key is False
    assert await storage.update("missing", SessionData(user_id=2)) is False


async def test_extend(storage) -> None:
    await storage.create(SessionData(user_id=1), session_id="s1", expiration=50)
    assert await storage.extend("s1", 100) is True


async def test_get_user_sessions(storage) -> None:
    await storage.create(SessionData(user_id=7), session_id="a")
    await storage.create(SessionData(user_id=7), session_id="b")
    await storage.create(SessionData(user_id=8), session_id="c")
    ids = set(await storage.get_user_sessions(7))
    assert ids == {"a", "b"}


async def test_delete_with_user_id_updates_index(storage) -> None:
    # passing user_id lets delete drop the session from the user index
    # without re-reading the record; the index stays consistent.
    await storage.create(SessionData(user_id=7), session_id="a")
    await storage.create(SessionData(user_id=7), session_id="b")
    assert await storage.delete("a", user_id=7) is True
    assert set(await storage.get_user_sessions(7)) == {"b"}


async def test_delete_without_user_id_still_updates_index(storage) -> None:
    # logout path: only the session id is known; delete reads the owner itself.
    await storage.create(SessionData(user_id=9), session_id="x")
    assert await storage.delete("x") is True
    assert await storage.get_user_sessions(9) == []


async def test_delete_pattern_prefix_semantics(storage) -> None:
    # both backends: delete_pattern(prefix) removes every key under that prefix
    # (memory used to be a no-op and diverge from Redis).
    await storage.create(SessionData(user_id=1), session_id="abc")
    await storage.create(SessionData(user_id=2), session_id="def")
    deleted = await storage.delete_pattern("t:")  # the fixture's prefix
    assert deleted == 2
    assert await storage.exists("abc") is False
    assert await storage.exists("def") is False


async def test_scan_keys_glob(storage) -> None:
    await storage.create(SessionData(user_id=1), session_id="abc")
    assert "t:abc" in await storage.scan_keys("t:*")
    assert await storage.scan_keys("nomatch:*") == []


async def test_set_if_absent_first_wins(storage) -> None:
    assert await storage.set_if_absent("tok", SessionData(user_id=1), expiration=50) is True
    # second attempt on the same key loses
    assert await storage.set_if_absent("tok", SessionData(user_id=2), expiration=50) is False
    # and the original value is the one that stuck
    got = await storage.get("tok", SessionData)
    assert got is not None and got.user_id == 1


async def test_set_if_absent_concurrent_single_winner(storage) -> None:
    results = await asyncio.gather(
        *[storage.set_if_absent("race", SessionData(user_id=i), expiration=50) for i in range(20)]
    )
    assert sum(1 for r in results if r is True) == 1  # exactly one winner


async def test_get_and_delete_returns_then_removes(storage) -> None:
    await storage.create(SessionData(user_id=5), session_id="g")
    got = await storage.get_and_delete("g", SessionData)
    assert got is not None and got.user_id == 5
    assert await storage.exists("g") is False
    assert await storage.get_and_delete("g", SessionData) is None  # second call: gone


async def test_get_and_delete_concurrent_single_consumer(storage) -> None:
    await storage.create(SessionData(user_id=5), session_id="once")
    results = await asyncio.gather(
        *[storage.get_and_delete("once", SessionData) for _ in range(20)]
    )
    assert sum(1 for r in results if r is not None) == 1  # consumed exactly once
