"""In-memory storage backend - for development and tests only."""

from __future__ import annotations

import fnmatch
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from ...constants import DEFAULT_SESSION_TTL_SECONDS
from ..base import AbstractSessionStorage, T
from ..constants import DEFAULT_STORAGE_PREFIX, MEMORY_SWEEP_EVERY_WRITES

__all__ = ["MemorySessionStorage"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class MemorySessionStorage(AbstractSessionStorage[T]):
    """Dict-backed storage. Not shared across processes - never use in production.

    Note:
        Eviction is lazy (on access to a key) plus an occasional full sweep on
        write, so abandoned keys don't accumulate unboundedly the way a
        purely-lazy dict would. It is still single-process and unsuitable for
        production - use the redis backend there.
    """

    def __init__(
        self, prefix: str = DEFAULT_STORAGE_PREFIX, expiration: int = DEFAULT_SESSION_TTL_SECONDS
    ):
        super().__init__(prefix=prefix, expiration=expiration)
        self.data: dict[str, bytes] = {}
        self.expiry: dict[str, datetime] = {}
        self._writes_since_sweep = 0

    def _check_expiry(self, key: str) -> bool:
        """Drop the entry if expired. Returns True if it was removed."""
        exp = self.expiry.get(key)
        if exp is not None and exp < _utcnow():
            self.data.pop(key, None)
            self.expiry.pop(key, None)
            return True
        return False

    def _maybe_sweep(self) -> None:
        """Periodically evict all expired keys so abandoned ones can't pile up."""
        self._writes_since_sweep += 1
        if self._writes_since_sweep < MEMORY_SWEEP_EVERY_WRITES:
            return
        self._writes_since_sweep = 0
        now = _utcnow()
        for key in [k for k, exp in list(self.expiry.items()) if exp < now]:
            self.data.pop(key, None)
            self.expiry.pop(key, None)

    async def create(
        self, data: T, session_id: str | None = None, expiration: int | None = None
    ) -> str:
        sid = session_id or self.generate_session_id()
        key = self.get_key(sid)
        ttl = expiration if expiration is not None else self.expiration
        self.data[key] = data.model_dump_json().encode()
        self.expiry[key] = _utcnow() + timedelta(seconds=ttl)
        self._maybe_sweep()
        return sid

    async def get(self, session_id: str, model_class: type[T]) -> T | None:
        key = self.get_key(session_id)
        if self._check_expiry(key):
            return None
        raw = self.data.get(key)
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
        if self._check_expiry(key) or key not in self.data:
            return False
        self.data[key] = data.model_dump_json().encode()
        if reset_expiration:
            ttl = expiration if expiration is not None else self.expiration
            self.expiry[key] = _utcnow() + timedelta(seconds=ttl)
        return True

    async def delete(self, session_id: str, user_id: Any = None) -> bool:
        """Delete a session. ``user_id`` is accepted for the shared contract but
        unused here (this backend keeps no separate per-user index)."""
        key = self.get_key(session_id)
        existed = key in self.data
        self.data.pop(key, None)
        self.expiry.pop(key, None)
        return existed

    async def extend(self, session_id: str, expiration: int | None = None) -> bool:
        key = self.get_key(session_id)
        if self._check_expiry(key) or key not in self.data:
            return False
        ttl = expiration if expiration is not None else self.expiration
        self.expiry[key] = _utcnow() + timedelta(seconds=ttl)
        return True

    async def exists(self, session_id: str) -> bool:
        key = self.get_key(session_id)
        if self._check_expiry(key):
            return False
        return key in self.data

    async def scan_keys(self, match: str | None = None) -> list[str]:
        """Enumerate keys by **glob** (e.g. ``"session:*"``), matching the Redis
        backend's semantics. ``None`` returns all keys."""
        if match is None:
            return list(self.data.keys())
        return [k for k in list(self.data.keys()) if fnmatch.fnmatchcase(k, match)]

    async def get_user_sessions(self, user_id: Any) -> list[str]:
        """Scan all sessions and return ids belonging to ``user_id``.

        Note:
            Reads the ``user_id`` field straight out of the serialized payload
            (the storage layer is model-agnostic, so it can't go through the
            model). The comparison is on the *stringified* id, matching how the
            Redis backend keys its per-user index - so a UUID PK (which a JSON
            round-trip turns into a string) still matches the ``UUID`` object the
            caller passes. Meaningful only for ``user_id``-bearing models;
            entries without that field are skipped.
        """
        target = str(user_id)
        sessions: list[str] = []
        for key in list(self.data.keys()):
            if self._check_expiry(key):
                continue
            try:
                payload = json.loads(self.data[key])
            except Exception:
                continue
            if isinstance(payload, dict) and "user_id" in payload:
                if str(payload["user_id"]) == target:
                    sessions.append(key[len(self.prefix) :])
        return sessions

    async def delete_pattern(self, pattern: str) -> int:
        """Delete keys whose name starts with ``pattern`` (matches ``{pattern}*``),
        the same prefix semantics as the Redis backend."""
        keys = await self.scan_keys(f"{pattern}*")
        count = 0
        for key in keys:
            sid = key[len(self.prefix) :] if key.startswith(self.prefix) else key
            if await self.delete(sid):
                count += 1
        return count
