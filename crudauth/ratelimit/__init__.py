"""Pluggable rate-limiting: one dumb backend, fixed-window check, lockout policy.

The backend is constructor-injected on [CRUDAuth][crudauth.crud_auth.CRUDAuth]
(``rate_limiter=``); login, register, and the email triggers are protected by
default. See the design in the project docs.
"""

from __future__ import annotations

import importlib.util
from typing import Any

from .backends import DatabaseRateLimiterBackend, MemoryRateLimiterBackend, RedisBackend
from .base import RateLimiterBackend
from .config import DEFAULT_RATE_LIMITS, KeyBy, LockoutConfig, RateLimit, RateLimitResolver
from .constants import REDIS_KEY_PREFIX
from .headers import RateLimitHeadersMiddleware
from .policy import LockoutPolicy

__all__ = [
    "DatabaseRateLimiterBackend",
    "RateLimiterBackend",
    "MemoryRateLimiterBackend",
    "RedisBackend",
    "RateLimit",
    "RateLimitResolver",
    "KeyBy",
    "DEFAULT_RATE_LIMITS",
    "LockoutPolicy",
    "LockoutConfig",
    "RateLimitHeadersMiddleware",
    "redis_rate_limiter",
]


def redis_rate_limiter(
    redis_url: str | None = None, client: Any = None, prefix: str = REDIS_KEY_PREFIX
) -> RateLimiterBackend:
    """Construct a Redis rate-limiter backend, guarding the optional dependency.

    Args:
        redis_url: Connection URL (defaults to localhost when omitted).
        client: A pre-built ``redis.asyncio`` client to reuse instead of a URL.
        prefix: Put before every key (default ``"crudauth:rl:"``). Two apps sharing one
            Redis (an admin panel beside the main app) need different ones, or a
            username locked out in one is locked out of the other.

    Returns:
        A [RedisBackend][crudauth.ratelimit.backends.redis.RedisBackend].

    Raises:
        ImportError: If the ``redis`` extra isn't installed.

    Example:
        ```python
        CRUDAuth(..., rate_limiter=redis_rate_limiter(redis_url=settings.REDIS_URL))
        ```
    """
    if client is None and importlib.util.find_spec("redis") is None:
        raise ImportError(
            "Redis rate limiter requires redis. Install: pip install 'crudauth[redis]'"
        )
    return RedisBackend(redis_url=redis_url, client=client, prefix=prefix)
