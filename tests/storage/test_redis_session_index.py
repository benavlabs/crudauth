"""The Redis per-user session index stays complete under concurrency and long activity."""

from __future__ import annotations

from typing import Any

import fakeredis.aioredis
import pytest
from redis.exceptions import ResponseError
from starlette.requests import Request

from crudauth import CRUDAuth, SessionTransport
from crudauth.storage import RedisSessionStorage
from crudauth.transports.session.schemas import SessionData

SECRET = "test-secret-key-0123456789-0123456789"


def _request() -> Request:
    return Request({"type": "http", "method": "GET", "headers": [], "client": ("1.2.3.4", 1234)})


def _manager(get_session, UserModel, client: Any) -> Any:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(csrf=False)],
        redis_client=client,
        warn_on_memory_backend=False,
    )
    return auth.sessions


async def test_logout_all_during_a_login_leaves_the_new_session_revocable(
    get_session, UserModel, monkeypatch
) -> None:
    client = fakeredis.aioredis.FakeRedis()
    manager = _manager(get_session, UserModel, client)
    write = client.set
    revoked_mid_login: list[int] = []

    async def write_after_a_logout_all(name: Any, *args: Any, **kwargs: Any) -> Any:
        if not revoked_mid_login and str(name).startswith("session:"):
            revoked_mid_login.append(await manager.revoke_all(7))
        return await write(name, *args, **kwargs)

    monkeypatch.setattr(client, "set", write_after_a_logout_all)
    session_id, _ = await manager.create_session(_request(), user_id=7)
    monkeypatch.setattr(client, "set", write)

    assert revoked_mid_login == [0]
    assert await manager.validate_session(session_id, update_activity=True) is not None
    assert manager.session_handle(session_id) in await manager.storage.get_user_sessions(7)
    assert await manager.revoke_all(7) == 1
    assert await manager.validate_session(session_id, update_activity=False) is None


async def test_a_revoke_during_an_activity_update_does_not_bring_the_session_back(
    get_session, UserModel, monkeypatch
) -> None:
    client = fakeredis.aioredis.FakeRedis()
    manager = _manager(get_session, UserModel, client)
    session_id, _ = await manager.create_session(_request(), user_id=8)
    open_pipeline = client.pipeline
    revoked_mid_update: list[int] = []

    def pipeline_revoking_before_exec(*args: Any, **kwargs: Any) -> Any:
        pipe = open_pipeline(*args, **kwargs)
        execute = pipe.execute

        async def revoke_then_execute(*execute_args: Any, **execute_kwargs: Any) -> Any:
            if not revoked_mid_update and pipe.watching:
                revoked_mid_update.append(await manager.revoke_all(8))
            return await execute(*execute_args, **execute_kwargs)

        monkeypatch.setattr(pipe, "execute", revoke_then_execute)
        return pipe

    monkeypatch.setattr(client, "pipeline", pipeline_revoking_before_exec)
    touched = await manager.validate_session(session_id, update_activity=True)
    monkeypatch.setattr(client, "pipeline", open_pipeline)

    assert revoked_mid_update == [1]
    assert touched is None
    assert await manager.storage.get(session_id, SessionData) is None
    assert session_id not in await manager.storage.get_user_sessions(8)


async def test_activity_keeps_the_user_index_alive(get_session, UserModel) -> None:
    client = fakeredis.aioredis.FakeRedis()
    manager = _manager(get_session, UserModel, client)
    session_id, _ = await manager.create_session(_request(), user_id=9)
    assert await client.ttl("session_users:9") > 0
    await client.expire("session_users:9", 30)

    await manager.validate_session(session_id, update_activity=True)

    assert await client.ttl("session_users:9") > manager.timeout_seconds_for({})


async def test_a_shorter_session_never_shortens_the_index_ttl(get_session, UserModel) -> None:
    client = fakeredis.aioredis.FakeRedis()
    manager = _manager(get_session, UserModel, client)
    await manager.create_session(_request(), user_id=10, expiration_seconds=100_000)
    long_lived = await client.ttl("session_users:10")

    short_id, _ = await manager.create_session(_request(), user_id=10)
    await manager.validate_session(short_id, update_activity=True)

    assert await client.ttl("session_users:10") >= long_lived - 1


async def test_initialize_fails_loudly_on_redis_older_than_7(monkeypatch) -> None:
    client = fakeredis.aioredis.FakeRedis()
    await RedisSessionStorage(client=client).initialize()

    async def expire_without_options(*args: Any, **kwargs: Any) -> Any:
        if kwargs.get("nx") or kwargs.get("gt"):
            raise ResponseError("wrong number of arguments for 'expire' command")
        return True

    monkeypatch.setattr(client, "expire", expire_without_options)

    with pytest.raises(RuntimeError, match="needs Redis 7.0 or newer"):
        await RedisSessionStorage(client=client).initialize()


async def test_initialize_passes_other_redis_errors_through(monkeypatch) -> None:
    client = fakeredis.aioredis.FakeRedis()

    async def read_only_replica(*args: Any, **kwargs: Any) -> Any:
        raise ResponseError("You can't write against a read only replica.")

    monkeypatch.setattr(client, "expire", read_only_replica)

    with pytest.raises(ResponseError, match="read only replica"):
        await RedisSessionStorage(client=client).initialize()


async def test_a_session_write_fails_loudly_on_redis_older_than_7(
    get_session, UserModel, monkeypatch
) -> None:
    client = fakeredis.aioredis.FakeRedis()
    manager = _manager(get_session, UserModel, client)

    class RejectedPipeline:
        async def __aenter__(self) -> RejectedPipeline:
            return self

        async def __aexit__(self, *exc_info: Any) -> None:
            return None

        def sadd(self, *args: Any) -> None:
            return None

        def expire(self, *args: Any, **kwargs: Any) -> None:
            return None

        async def execute(self) -> None:
            raise ResponseError(
                "Command # 2 (EXPIRE session_users:1 5400 NX) of pipeline caused error: "
                "wrong number of arguments for 'expire' command"
            )

    monkeypatch.setattr(client, "pipeline", lambda **kwargs: RejectedPipeline())

    with pytest.raises(RuntimeError, match="needs Redis 7.0 or newer"):
        await manager.create_session(_request(), user_id=1)


async def test_activity_puts_a_session_back_into_a_lost_index(get_session, UserModel) -> None:
    client = fakeredis.aioredis.FakeRedis()
    manager = _manager(get_session, UserModel, client)
    session_id, _ = await manager.create_session(_request(), user_id=11)
    await client.delete("session_users:11")

    await manager.validate_session(session_id, update_activity=True)

    assert manager.session_handle(session_id) in await manager.storage.get_user_sessions(11)
    assert await manager.revoke_all(11) == 1
