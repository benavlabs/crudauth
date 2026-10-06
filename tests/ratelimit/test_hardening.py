"""Rate-limit and lockout keys, counters and configuration that can't be bypassed or misconfigured."""

from __future__ import annotations

import logging
from typing import Any

import fakeredis.aioredis
import httpx
import pytest
from fastapi import Depends, FastAPI
from starlette.requests import Request

from crudauth import AuthHooks, BearerTransport, CookieConfig, CRUDAuth, SessionTransport
from crudauth.ratelimit import (
    KeyBy,
    LockoutConfig,
    LockoutPolicy,
    MemoryRateLimiterBackend,
    RateLimit,
    RedisBackend,
)
from crudauth.ratelimit import base as ratelimit_base
from crudauth.ratelimit.constants import LOCKOUT_NAMESPACE
from crudauth.utils import client_ip_key, get_client_ip

SECRET = "test-secret-key-0123456789-0123456789"
PASSWORD = "pw123456"


def _request(headers: list[tuple[str, str]], client: str = "10.0.0.9") -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "headers": [(name.encode(), value.encode()) for name, value in headers],
            "client": (client, 1234),
        }
    )


def _app(auth: CRUDAuth) -> FastAPI:
    app = FastAPI()
    app.include_router(auth.router)
    return app


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def test_repeated_forwarded_for_headers_are_read_as_one_chain() -> None:
    request = _request([("x-forwarded-for", "6.6.6.6"), ("x-forwarded-for", "203.0.113.9")])

    assert get_client_ip(request, trusted_hops=1) == "203.0.113.9"
    assert get_client_ip(request, trusted_hops=2) == "6.6.6.6"


async def test_a_counter_without_a_ttl_gets_one_on_its_next_increment() -> None:
    client = fakeredis.aioredis.FakeRedis()
    backend = RedisBackend(client=client)
    key = backend._k("lockout:ip:1.1.1.1")
    await client.incrby(key, 4)

    assert await backend.increment("lockout:ip:1.1.1.1", 1, 60) == 5
    assert 0 < await client.ttl(key) <= 60
    await client.expire(key, 30)
    await backend.increment("lockout:ip:1.1.1.1", 1, 60)
    assert await client.ttl(key) <= 30
    await backend.close()


async def test_logging_into_your_own_account_does_not_launder_a_spray() -> None:
    policy = LockoutPolicy(MemoryRateLimiterBackend(), max_attempts=5)
    blocked = 0
    for attempt in range(200):
        allowed, _, _ = await policy.check_and_record("10.0.0.1", f"victim{attempt}")
        blocked += not allowed
        if attempt % 4 == 3:
            await policy.check_and_record("10.0.0.1", "attacker", success=True)

    assert blocked > 150


async def test_a_users_own_typos_do_not_count_against_their_ip_after_they_log_in() -> None:
    policy = LockoutPolicy(MemoryRateLimiterBackend(), max_attempts=5)
    for _ in range(4):
        await policy.check_and_record("10.0.0.1", "alice")
    await policy.check_and_record("10.0.0.1", "alice", success=True)

    results = [(await policy.check_and_record("10.0.0.1", "bob"))[0] for _ in range(5)]

    assert results == [True] * 5


async def test_case_variants_of_a_username_share_a_lockout() -> None:
    policy = LockoutPolicy(MemoryRateLimiterBackend(), max_attempts=3)
    variants = ["bob", "Bob", "BOB", " bOb "]

    results = [
        (await policy.check_and_record(f"10.0.0.{i}", name))[0] for i, name in enumerate(variants)
    ]

    assert results == [True, True, True, False]


def test_ipv6_clients_key_by_their_64() -> None:
    assert client_ip_key("2001:db8:1:2:aaaa::1") == client_ip_key("2001:db8:1:2:bbbb::2")
    assert client_ip_key("2001:db8:1:2::1") != client_ip_key("2001:db8:1:3::1")
    assert client_ip_key("::ffff:203.0.113.7") == "203.0.113.7"
    assert client_ip_key("203.0.113.7") == "203.0.113.7"
    assert client_ip_key("unknown") == "unknown"


async def test_ipv6_addresses_in_one_64_share_the_lockout() -> None:
    policy = LockoutPolicy(MemoryRateLimiterBackend(), max_attempts=3)

    results = [
        (await policy.check_and_record(f"2001:db8::{i:x}", f"user{i}"))[0] for i in range(1, 5)
    ]

    assert results == [True, True, True, False]


async def test_an_ip_rate_limit_is_shared_across_an_ipv6_64(
    get_session: Any, UserModel: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The window is keyed by wall-clock time; pin it so the requests can't straddle two windows.
    monkeypatch.setattr(ratelimit_base.time, "time", lambda: 1_800_000_000.0)
    auth = CRUDAuth(
        session=get_session, user_model=UserModel, SECRET_KEY=SECRET, trusted_proxy_hops=1
    )
    app = FastAPI()

    @app.get("/limited", dependencies=[Depends(auth.rate_limit("limited", RateLimit(2, 60)))])
    async def limited():
        return {}

    async with _client(app) as client:
        statuses = [
            (
                await client.get("/limited", headers={"x-forwarded-for": f"2001:db8::{i:x}"})
            ).status_code
            for i in range(1, 4)
        ]

    assert statuses == [200, 200, 429]
    assert KeyBy.IP == "ip"


async def test_the_register_limit_is_shared_across_an_ipv6_64(get_session, UserModel) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        trusted_proxy_hops=1,
        rate_limits={"register": RateLimit(2, 3600)},
    )
    app = _app(auth)
    await auth.initialize()
    async with _client(app) as client:
        statuses = [
            (
                await client.post(
                    "/register",
                    json={"email": f"u{i}@x.com", "username": f"u{i}", "password": PASSWORD},
                    headers={"x-forwarded-for": f"2001:db8::{i:x}"},
                )
            ).status_code
            for i in range(1, 4)
        ]
    await auth.shutdown()

    assert statuses == [200, 200, 429]


@pytest.mark.parametrize(("times", "seconds"), [(5, 0), (5, -1), (-1, 60)])
def test_an_invalid_rate_limit_fails_at_construction(times: int, seconds: int) -> None:
    with pytest.raises(ValueError):
        RateLimit(times, seconds)


def test_an_unknown_rate_limits_key_fails_at_construction(get_session, UserModel) -> None:
    with pytest.raises(ValueError, match="password_reset"):
        CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY=SECRET,
            rate_limits={"password_reset": RateLimit(3, 60)},
        )


@pytest.mark.parametrize(
    "config", [{"max_attempts": 0}, {"lockout_base_seconds": 0}, {"on_login_success": "clear"}]
)
def test_an_invalid_lockout_config_fails_at_construction(config: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        LockoutConfig(**config)


async def test_a_bearer_only_app_configures_the_login_lockout(get_session, UserModel) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[BearerTransport(refresh="body")],
        lockout=LockoutConfig(max_attempts=2),
    )
    app = _app(auth)
    await auth.initialize()
    async with _client(app) as client:
        await client.post(
            "/register", json={"email": "a@x.com", "username": "alice", "password": PASSWORD}
        )
        statuses = [
            (
                await client.post("/token", data={"username": "alice", "password": "wrong"})
            ).status_code
            for _ in range(3)
        ]
    await auth.shutdown()

    assert statuses == [401, 401, 429]


def test_the_lockout_cannot_be_configured_twice(get_session, UserModel) -> None:
    with pytest.raises(ValueError, match="configured twice"):
        CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY=SECRET,
            transports=[SessionTransport(login_max_attempts=3)],
            lockout=LockoutConfig(max_attempts=10),
        )


async def test_a_failing_hook_leaves_the_operation_complete(get_session, UserModel, caplog) -> None:
    def fail(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("hook down")

    hooks = AuthHooks(on_after_register=fail, on_after_login=fail, on_after_password_changed=fail)
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False), max_sessions_per_user=2)],
        hooks=hooks,
    )
    app = _app(auth)
    await auth.initialize()
    with caplog.at_level(logging.ERROR, logger="crudauth.hooks"):
        async with _client(app) as client:
            register = await client.post(
                "/register", json={"email": "a@x.com", "username": "alice", "password": PASSWORD}
            )
            logins = [
                await client.post("/login", data={"username": "alice", "password": PASSWORD})
                for _ in range(3)
            ]
            me = await client.get("/me")
            change = await client.post(
                "/change-password",
                json={"current_password": PASSWORD, "new_password": "changed-pw-1"},
                headers={"X-CSRF-Token": logins[-1].json()["csrf_token"]},
            )
    user_id = me.json()["user_id"]
    sessions = await auth.sessions.list_for_user(user_id)
    await auth.shutdown()

    assert register.status_code == 200
    assert [login.status_code for login in logins] == [200, 200, 200]
    assert (me.status_code, change.status_code) == (200, 200)
    assert len(sessions) == 1
    assert caplog.text.count("hook failed") == 5


async def test_shutdown_closes_every_component_when_one_fails(
    get_session, UserModel, monkeypatch
) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        redis_url="redis://auth-redis.internal:6379/0",
        warn_on_memory_backend=False,
    )
    closed: list[str] = []

    async def failing_shutdown() -> None:
        raise RuntimeError("transport close failed")

    async def record_close() -> None:
        closed.append("redis")

    monkeypatch.setattr(auth.transports[0], "shutdown", failing_shutdown)
    monkeypatch.setattr(auth._owned_redis, "aclose", record_close)

    with pytest.raises(RuntimeError, match="transport close failed"):
        await auth.shutdown()
    assert closed == ["redis"]


@pytest.mark.parametrize("backend_name", ["memory", "redis"])
async def test_forgetting_an_attempt_takes_back_one_failure_and_never_goes_negative(
    backend_name: str,
) -> None:
    backend = (
        MemoryRateLimiterBackend()
        if backend_name == "memory"
        else RedisBackend(client=fakeredis.aioredis.FakeRedis())
    )
    policy = LockoutPolicy(backend, max_attempts=5)
    await policy.forget_attempt("10.0.0.1", "alice")
    for _ in range(3):
        await policy.check_and_record("10.0.0.1", "Alice")
    await policy.forget_attempt("10.0.0.1", "alice")

    assert await backend.get_count(f"{LOCKOUT_NAMESPACE}:user:alice") == 2
    assert await backend.get_count(f"{LOCKOUT_NAMESPACE}:ip:10.0.0.1") == 2
    assert await backend.get_count(f"{LOCKOUT_NAMESPACE}:pair:10.0.0.1:alice") == 2
    await backend.close()
