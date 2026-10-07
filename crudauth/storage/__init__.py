"""Pluggable server-side storage for sessions, CSRF tokens, and OAuth state."""

from __future__ import annotations

from typing import Any, TypeVar

from pydantic import BaseModel

from ..constants import DEFAULT_SESSION_TTL_SECONDS
from .backends.database import DatabaseSessionStorage, DatabaseStore
from .backends.memory import MemorySessionStorage
from .backends.redis import RedisSessionStorage
from .base import AbstractSessionStorage
from .constants import BACKEND_DATABASE, BACKEND_MEMORY, BACKEND_REDIS, DEFAULT_STORAGE_PREFIX

__all__ = [
    "AbstractSessionStorage",
    "DatabaseSessionStorage",
    "DatabaseStore",
    "MemorySessionStorage",
    "RedisSessionStorage",
    "get_session_storage",
]

T = TypeVar("T", bound=BaseModel)


def get_session_storage(
    backend: str = BACKEND_MEMORY,
    *,
    prefix: str = DEFAULT_STORAGE_PREFIX,
    expiration: int = DEFAULT_SESSION_TTL_SECONDS,
    redis_url: str | None = None,
    client: Any = None,
    database: DatabaseStore | None = None,
    **kwargs: Any,
) -> AbstractSessionStorage[Any]:
    """Construct a storage backend by name.

    Args:
        backend: ``"memory"`` (default, dev/testing), ``"redis"`` or ``"database"``.
        prefix: Key namespace prefix.
        expiration: Default TTL in seconds.
        redis_url: Connection URL for ``backend="redis"`` when no ``client`` is given;
            localhost when omitted.
        client: Existing async Redis client. The caller owns its lifecycle.
        database: The [DatabaseStore][crudauth.storage.backends.database.DatabaseStore]
            to keep values in, for ``backend="database"``.

    Returns:
        An [AbstractSessionStorage][crudauth.storage.base.AbstractSessionStorage] for the requested backend.

    Raises:
        ValueError: If ``backend`` isn't one of those three, or is ``"database"``
            without a ``database``.
    """
    backend = (backend or BACKEND_MEMORY).lower()
    if backend == BACKEND_MEMORY:
        return MemorySessionStorage(prefix=prefix, expiration=expiration)
    if backend == BACKEND_REDIS:
        return RedisSessionStorage(
            prefix=prefix, expiration=expiration, redis_url=redis_url, client=client, **kwargs
        )
    if backend == BACKEND_DATABASE:
        if database is None:
            raise ValueError("backend='database' needs a DatabaseStore (database=...)")
        return DatabaseSessionStorage(database, prefix=prefix, expiration=expiration)
    raise ValueError(
        f"Unknown session backend: {backend!r} (expected 'memory', 'redis' or 'database')"
    )
