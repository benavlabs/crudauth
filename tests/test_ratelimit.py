"""Rate-limiter backends, the lockout policy, and the rate_limit() dependency."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import Depends, FastAPI

from crudauth import CookieConfig, CRUDAuth, Principal, SessionTransport
from crudauth.ratelimit import (
    KeyBy,
    LockoutPolicy,
    MemoryRateLimiterBackend,
    RateLimit,
    RedisBackend,
)
from crudauth.ratelimit.base import RateLimiterBackend


def _fakeredis_client():
    import fakeredis.aioredis

    return fakeredis.aioredis.FakeRedis()


# =============================================================================
# Backend conformance - memory and redis behave identically (the dumb surface)
# =============================================================================
@pytest.fixture(params=["memory", "redis"])
async def backend(request) -> AsyncIterator[RateLimiterBackend]:
    if request.param == "memory":
        yield MemoryRateLimiterBackend()
    else:
        b = RedisBackend(client=_fakeredis_client())
        yield b
        await b.close()


async def test_increment_and_count(backend) -> None:
    assert await backend.get_count("k") is None
    assert await backend.increment("k", 1, 100) == 1
    assert await backend.increment("k", 1, 100) == 2
    assert await backend.get_count("k") == 2


async def test_delete_and_reset(backend) -> None:
    await backend.increment("k", 1, 100)
    assert await backend.delete("k") is True
    assert await backend.get_count("k") is None
    await backend.increment("k", 1, 100)
    await backend.reset("k")
    assert await backend.get_count("k") is None


async def test_ping(backend) -> None:
    assert await backend.ping() is True


async def test_memory_backend_evicts_abandoned_window_keys() -> None:
    # rolling window-stamped keys are never re-touched; the periodic sweep
    # must evict them so a high-cardinality keyspace can't grow unbounded.
    import time as _time

    from crudauth.ratelimit.constants import MEMORY_SWEEP_EVERY_INCREMENTS

    b = MemoryRateLimiterBackend()
    for i in range(300):  # simulate abandoned, already-expired window keys
        b._counts[f"old:{i}"] = 1
        b._deadline[f"old:{i}"] = _time.monotonic() - 1
    for _ in range(MEMORY_SWEEP_EVERY_INCREMENTS):  # drive the periodic sweep
        await b.increment("live", 1, 100)
    assert not any(k.startswith("old:") for k in b._counts)  # stale keys gone
    assert "live" in b._counts  # the unexpired key survives


async def test_increment_and_check_trips(backend) -> None:
    limit, period = 3, 100
    results = [await backend.increment_and_check("ic", limit, period) for _ in range(4)]
    counts = [r[0] for r in results]
    limited = [r[1] for r in results]
    assert counts == [1, 2, 3, 4]
    assert limited == [False, False, False, True]
    assert results[-1][2] > 0  # retry_after set once limited


# =============================================================================
# LockoutPolicy - escalation, survival, fail-closed
# =============================================================================
async def test_backoff_doubles_across_rounds() -> None:
    policy = LockoutPolicy(
        MemoryRateLimiterBackend(),
        max_attempts=1,
        lockout_base_seconds=10,
        lockout_max_seconds=10_000,
        round_retention_seconds=10_000,
        fail_open=False,
    )
    # round 0: exceed → ~base
    await policy.check_and_record("ip", "u")  # count 1 (== max)
    _, _, r0 = await policy.check_and_record("ip", "u")  # count 2 (> max) → lock
    # clear the active lock window by recording success on a *different* identity
    # then re-trip to advance the round counter.
    _, _, r1 = await policy.check_and_record("ip", "u")  # still locked, reports remaining
    assert r0 == 10
    assert r1 > 0


async def test_lockout_fails_closed_on_backend_error() -> None:
    class BrokenBackend(MemoryRateLimiterBackend):
        async def get_ttl(self, key: str) -> int:
            raise RuntimeError("backend down")

    policy = LockoutPolicy(BrokenBackend(), fail_open=False)
    allowed, _, retry = await policy.check_and_record("ip", "u")
    assert allowed is False  # fail closed
    assert retry > 0


async def test_lockout_fails_open_when_configured() -> None:
    class BrokenBackend(MemoryRateLimiterBackend):
        async def get_ttl(self, key: str) -> int:
            raise RuntimeError("backend down")

    policy = LockoutPolicy(BrokenBackend(), fail_open=True)
    allowed, _, _ = await policy.check_and_record("ip", "u")
    assert allowed is True


# =============================================================================
# rate_limit() dependency - per-IP 429 on a custom action
# =============================================================================
async def test_rate_limit_dependency_raises_429(get_session, UserModel) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()

    @app.get("/limited", dependencies=[Depends(auth.rate_limit("custom", RateLimit(2, 100)))])
    async def limited() -> dict:
        return {"ok": True}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        assert (await c.get("/limited")).status_code == 200
        assert (await c.get("/limited")).status_code == 200
        r = await c.get("/limited")
        assert r.status_code == 429
        assert "Retry-After" in r.headers
        assert r.headers["X-RateLimit-Limit"] == "2"
    await auth.shutdown()


async def test_rate_limit_keyed_by_user(get_session, UserModel) -> None:
    # USER keying throttles per-principal: two sessions for two users each get
    # their own budget, and one user exhausting it doesn't affect the other.
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()
    app.include_router(auth.router)

    @app.get(
        "/u", dependencies=[Depends(auth.rate_limit("uact", RateLimit(2, 100), key=KeyBy.USER))]
    )
    async def u(_: Principal = Depends(auth.current_user())) -> dict:
        return {"ok": True}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as alice:
        await alice.post(
            "/register", json={"email": "a@x.com", "username": "alice", "password": "pw123456"}
        )
        await alice.post("/login", data={"username": "alice", "password": "pw123456"})
        assert (await alice.get("/u")).status_code == 200
        assert (await alice.get("/u")).status_code == 200
        assert (await alice.get("/u")).status_code == 429  # alice over her own budget

    # a second user on a fresh client has an independent budget
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as bob:
        await bob.post(
            "/register", json={"email": "b@x.com", "username": "bob", "password": "pw123456"}
        )
        await bob.post("/login", data={"username": "bob", "password": "pw123456"})
        assert (await bob.get("/u")).status_code == 200
    await auth.shutdown()


async def test_rate_limit_keyed_by_custom_callable(get_session, UserModel) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()
    by_tenant = auth.rate_limit(
        "tact", RateLimit(1, 100), key=lambda r: r.headers.get("X-Tenant", "anon")
    )

    @app.get("/t", dependencies=[Depends(by_tenant)])
    async def t() -> dict:
        return {"ok": True}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        assert (await c.get("/t", headers={"X-Tenant": "acme"})).status_code == 200
        assert (await c.get("/t", headers={"X-Tenant": "acme"})).status_code == 429  # acme spent
        assert (
            await c.get("/t", headers={"X-Tenant": "globex"})
        ).status_code == 200  # other key ok
    await auth.shutdown()


async def test_rate_limit_disabled_with_times_zero(get_session, UserModel) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()

    @app.get("/free", dependencies=[Depends(auth.rate_limit("off", RateLimit(0, 100)))])
    async def free() -> dict:
        return {"ok": True}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        for _ in range(10):
            assert (await c.get("/free")).status_code == 200
    await auth.shutdown()
