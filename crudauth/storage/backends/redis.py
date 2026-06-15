"""Redis storage backend (production). Requires ``crudauth[redis]``."""

from __future__ import annotations

import json
from typing import Any

from ...constants import DEFAULT_SESSION_TTL_SECONDS, USER_INDEX_TTL_BUFFER_SECONDS
from ..base import AbstractSessionStorage, T
from ..constants import DEFAULT_REDIS_URL, DEFAULT_STORAGE_PREFIX, USER_INDEX_SUFFIX

__all__ = ["RedisSessionStorage"]


class RedisSessionStorage(AbstractSessionStorage[T]):
    """Async Redis backend with a per-user session index for fast enumeration.

    Layout:
        * ``{prefix}{session_id}`` -> serialized model (TTL = expiration)
        * ``{prefix_root}_users:{user_id}`` -> SET of session ids (TTL = expiration + 1h)

    Note:
        Pass an existing ``client=`` to share one connection pool with other
        redis-backed components (e.g. the rate-limiter backend); otherwise each
        constructs its own pool to the same server.
    """

    def __init__(
        self,
        prefix: str = DEFAULT_STORAGE_PREFIX,
        expiration: int = DEFAULT_SESSION_TTL_SECONDS,
        redis_url: str | None = None,
        client: Any = None,
        **_: Any,
    ):
        super().__init__(prefix=prefix, expiration=expiration)
        if client is not None:
            self.client = client
        else:
            try:
                from redis.asyncio import Redis
            except ImportError as exc:  # pragma: no cover
                raise ImportError(
                    "Redis backend requires the 'redis' package. "
                    "Install with: pip install 'crudauth[redis]'"
                ) from exc
            self.client = Redis.from_url(redis_url or DEFAULT_REDIS_URL, decode_responses=False)
        self.user_sessions_prefix = f"{prefix.rstrip(':')}{USER_INDEX_SUFFIX}"

    def _user_key(self, user_id: Any) -> str:
        return f"{self.user_sessions_prefix}{user_id}"

    async def initialize(self) -> None:
        await self.client.ping()

    async def close(self) -> None:
        await self.client.aclose()

    async def create(
        self, data: T, session_id: str | None = None, expiration: int | None = None
    ) -> str:
        sid = session_id or self.generate_session_id()
        key = self.get_key(sid)
        ttl = expiration if expiration is not None else self.expiration
        payload = data.model_dump_json().encode()
        user_id = getattr(data, "user_id", None)
        async with self.client.pipeline(transaction=True) as pipe:
            pipe.set(key, payload, ex=ttl)
            if user_id is not None:
                ukey = self._user_key(user_id)
                pipe.sadd(ukey, sid)
                pipe.expire(ukey, ttl + USER_INDEX_TTL_BUFFER_SECONDS)
            await pipe.execute()
        return sid

    async def get(self, session_id: str, model_class: type[T]) -> T | None:
        raw = await self.client.get(self.get_key(session_id))
        if raw is None:
            return None
        return model_class.model_validate_json(raw)

    async def update(
        self,
        session_id: str,
        data: T,
        reset_expiration: bool = True,
        expiration: int | None = None,
    ) -> bool:
        key = self.get_key(session_id)
        if not await self.client.exists(key):
            return False
        payload = data.model_dump_json().encode()
        ttl = expiration if expiration is not None else self.expiration
        if reset_expiration:
            await self.client.set(key, payload, ex=ttl)
        else:
            await self.client.set(key, payload, keepttl=True)
        return True

    async def delete(self, session_id: str, user_id: Any = None) -> bool:
        """Delete a session and drop it from its owner's index.

        Note:
            When ``user_id`` is given (the indexed terminate paths know it), the
            owner read is skipped entirely. When it's ``None`` (e.g. logout with
            only a cookie), the record is read once to find the owner so the
            user index stays consistent. The index assumes a ``user_id``-bearing
            model; for other models nothing is read or indexed.
        """
        key = self.get_key(session_id)
        if user_id is None:
            raw = await self.client.get(key)
            if raw is not None:
                try:
                    user_id = json.loads(raw).get("user_id")
                except Exception:
                    user_id = None
        async with self.client.pipeline(transaction=True) as pipe:
            pipe.delete(key)
            if user_id is not None:
                pipe.srem(self._user_key(user_id), session_id)
            results = await pipe.execute()
        return bool(results[0])

    async def extend(self, session_id: str, expiration: int | None = None) -> bool:
        ttl = expiration if expiration is not None else self.expiration
        return bool(await self.client.expire(self.get_key(session_id), ttl))

    async def exists(self, session_id: str) -> bool:
        return bool(await self.client.exists(self.get_key(session_id)))

    async def set_if_absent(self, session_id: str, data: T, expiration: int | None = None) -> bool:
        """Atomic create-if-absent via ``SET key value NX EX ttl`` (single round trip)."""
        ttl = expiration if expiration is not None else self.expiration
        payload = data.model_dump_json().encode()
        result = await self.client.set(self.get_key(session_id), payload, ex=ttl, nx=True)
        return result is not None

    async def get_and_delete(self, session_id: str, model_class: type[T]) -> T | None:
        """Atomic read-and-delete via a ``MULTI/EXEC`` pipeline (portable; no GETDEL dependency).

        Note:
            Used for single-use values without a per-user index (OAuth ``state``),
            so it bypasses the user-index bookkeeping in [delete]
            [crudauth.storage.backends.redis.RedisSessionStorage.delete].
        """
        key = self.get_key(session_id)
        async with self.client.pipeline(transaction=True) as pipe:
            pipe.get(key)
            pipe.delete(key)
            raw, _ = await pipe.execute()
        if raw is None:
            return None
        return model_class.model_validate_json(raw)

    async def get_user_sessions(self, user_id: Any) -> list[str]:
        members = await self.client.smembers(self._user_key(user_id))
        return [m.decode() if isinstance(m, bytes) else m for m in members]

    async def scan_keys(self, match: str | None = None) -> list[str]:
        pattern = match or f"{self.prefix}*"
        keys: list[str] = []
        async for key in self.client.scan_iter(match=pattern):
            keys.append(key.decode() if isinstance(key, bytes) else key)
        return keys

    async def delete_pattern(self, pattern: str) -> int:
        count = 0
        async for key in self.client.scan_iter(match=f"{pattern}*"):
            count += await self.client.delete(key)
        return count
