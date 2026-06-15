"""In-process rate-limiter backend - the default; fine for single-process dev."""

from __future__ import annotations

import time

from ..base import RateLimiterBackend
from ..constants import MEMORY_SWEEP_EVERY_INCREMENTS

__all__ = ["MemoryRateLimiterBackend"]


class MemoryRateLimiterBackend(RateLimiterBackend):
    """Dict-backed counters with monotonic TTLs. Not shared across processes.

    Note:
        Window-stamped keys (``{key}:{window_start}``) roll every window, so an
        abandoned past window's key is never accessed again. Eviction is
        therefore lazy-on-access **plus** an occasional full sweep on increment,
        so a high-cardinality keyspace (per-IP / per-email) can't grow unbounded.
        Still single-process - use the redis backend in production.
    """

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}
        self._deadline: dict[str, float] = {}
        self._increments_since_sweep = 0

    def _gc(self, key: str) -> None:
        deadline = self._deadline.get(key)
        if deadline is not None and deadline < time.monotonic():
            self._counts.pop(key, None)
            self._deadline.pop(key, None)

    def _maybe_sweep(self) -> None:
        self._increments_since_sweep += 1
        if self._increments_since_sweep < MEMORY_SWEEP_EVERY_INCREMENTS:
            return
        self._increments_since_sweep = 0
        now = time.monotonic()
        for key in [k for k, dl in list(self._deadline.items()) if dl < now]:
            self._counts.pop(key, None)
            self._deadline.pop(key, None)

    async def increment(self, key: str, amount: int = 1, expiry: int | None = None) -> int:
        """Increment; arm the TTL only on first touch (key absent from the
        deadline map) - the contract from [RateLimiterBackend.increment][crudauth.ratelimit.base.RateLimiterBackend.increment]."""
        self._gc(key)
        self._counts[key] = self._counts.get(key, 0) + amount
        if expiry is not None and key not in self._deadline:
            self._deadline[key] = time.monotonic() + expiry
        self._maybe_sweep()
        return self._counts[key]

    async def increment_and_refresh_ttl(
        self, key: str, amount: int = 1, expiry: int | None = None
    ) -> int:
        """Increment and slide the TTL forward on every call (see the base method)."""
        self._gc(key)
        self._counts[key] = self._counts.get(key, 0) + amount
        if expiry is not None:
            self._deadline[key] = time.monotonic() + expiry
        self._maybe_sweep()
        return self._counts[key]

    async def get_count(self, key: str) -> int | None:
        self._gc(key)
        return self._counts.get(key)

    async def get_ttl(self, key: str) -> int:
        self._gc(key)
        deadline = self._deadline.get(key)
        if deadline is None:
            return 0
        return max(0, int(deadline - time.monotonic()))

    async def reset(self, key: str) -> None:
        await self.delete(key)

    async def delete(self, key: str) -> bool:
        existed = key in self._counts
        self._counts.pop(key, None)
        self._deadline.pop(key, None)
        return existed

    async def ping(self) -> bool:
        return True
