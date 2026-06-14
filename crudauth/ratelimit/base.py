"""The rate-limiter backend port.

The *required* surface is a dumb counter - five abstract methods plus an
overridable ``get_ttl``. The fixed-window check ([increment_and_check][crudauth.ratelimit.base.RateLimiterBackend.increment_and_check])
is provided once on the base class over that counter, so a third backend is a
handful of trivial methods, not a window-math reimplementation.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod

__all__ = ["RateLimiterBackend"]


class RateLimiterBackend(ABC):
    """Async counter store backing rate limiting and login lockout.

    A backend implements the dumb primitives; the package layers the
    fixed-window check and the escalating [LockoutPolicy][crudauth.ratelimit.policy.LockoutPolicy]
    on top. The primitives **raise** on a backend error - the policy layer
    catches and decides fail-open vs fail-closed, so one backend can serve both
    fail-open window limits and fail-closed lockout.

    Example:
        ```python
        from crudauth.ratelimit import MemoryRateLimiterBackend
        backend = MemoryRateLimiterBackend()
        count, limited, retry_after = await backend.increment_and_check("ip:1.2.3.4", 5, 60)
        ```
    """

    @abstractmethod
    async def increment(self, key: str, amount: int = 1, expiry: int | None = None) -> int:
        """Increment ``key`` by ``amount``, return the new count.

        Note:
            **TTL is armed on first touch only.** ``expiry`` must be applied when
            the key is created (the increment that brings it into existence) and
            NOT re-armed on subsequent increments - otherwise sustained load
            would push the TTL forward forever and a fixed window would never
            close. Both in-tree backends honor this (Redis: ``value == amount``;
            memory: key absent from the deadline map); a new backend must too.
        """

    @abstractmethod
    async def increment_and_refresh_ttl(
        self, key: str, amount: int = 1, expiry: int | None = None
    ) -> int:
        """Increment ``key`` and (re-)arm its TTL on **every** call, atomically.

        The counterpart to [increment][crudauth.ratelimit.base.RateLimiterBackend.increment]'s
        first-touch-only TTL: this slides the expiry forward on each call, for a
        counter that must live as long as activity continues - the lockout
        escalation "rounds" counter, so a slow, paced attack can't let it expire
        and reset the backoff. The increment and the TTL re-arm MUST be atomic
        (one round trip on a networked backend) so a concurrent attempt can't
        interleave between them.
        """

    @abstractmethod
    async def get_count(self, key: str) -> int | None:
        """Current counter value, or ``None`` if the key is absent."""

    @abstractmethod
    async def reset(self, key: str) -> None:
        """Reset ``key`` to absent (alias of delete that ignores the result)."""

    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete ``key``; return whether it existed."""

    @abstractmethod
    async def ping(self) -> bool:
        """Liveness check for the backing store."""

    async def get_ttl(self, key: str) -> int:
        """Remaining TTL in seconds for ``key`` (``0`` if unknown/absent).

        Overridable; the escalating lockout policy uses it. The default returns
        ``0`` for backends that can't report TTL.

        Note:
            [LockoutPolicy][crudauth.ratelimit.policy.LockoutPolicy] reads this to detect an
            active lockout. A backend that leaves the default ``0`` still counts
            attempts but can never *hold a lockout open* - so any backend used
            with lockout MUST implement ``get_ttl`` (both in-tree backends do).
        """
        return 0

    async def increment_and_check(
        self, key: str, limit: int, period: int, *, fail_open: bool = True
    ) -> tuple[int, bool, int]:
        """Fixed-window limit check over the dumb counter.

        Override for a single-call atomic version (Redis does). The window-stamped
        key is what makes re-expiring on every increment correct: the key rolls
        each window, so old windows expire on their own rather than the TTL being
        pushed forever under sustained load.

        Args:
            key: Logical counter key (an action+identity namespace).
            limit: Max events allowed within ``period``.
            period: Window length in seconds.
            fail_open: On a backend error, allow (``True``) or block (``False``).

        Returns:
            ``(count, limited, retry_after_seconds)``.
        """
        now = int(time.time())
        window_start = now - (now % period)
        wkey = f"{key}:{window_start}"
        try:
            count = await self.increment(wkey, 1, period)
        except Exception:
            return (0, False, 0) if fail_open else (limit + 1, True, period)
        if count <= limit:
            return count, False, 0
        return count, True, period - (now - window_start)

    async def initialize(self) -> None:
        """Open connections / warm up. Default no-op."""

    async def close(self) -> None:
        """Release resources. Default no-op."""
