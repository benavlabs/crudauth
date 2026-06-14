"""Internal keyspace + tuning constants for rate limiting.

(Policy *values* and types - [RateLimit][crudauth.ratelimit.config.RateLimit], [KeyBy][crudauth.ratelimit.config.KeyBy],
``DEFAULT_RATE_LIMITS`` - live in [crudauth.ratelimit.config][crudauth.ratelimit.config].)
"""

from __future__ import annotations

# Login-lockout keys live under this namespace, e.g. ``login:ip:<ip>``. They are
# TTL'd and must never be bulk-deleted by the session cleanup sweep, which would
# clear an attacker's accumulated failures.
LOCKOUT_NAMESPACE = "login"

# Namespace for the per-endpoint ``rate_limit()`` dependency keys.
RATE_LIMIT_NAMESPACE = "ratelimit"

# Sudo-lockout keys live under this namespace (``sudo:fail:<uid>`` /
# ``sudo:lock:<uid>``), kept separate from the ``login`` lockout so a sudo
# brute force can't reset login counters or vice versa.
SUDO_NAMESPACE = "sudo"

# Default Redis key prefix for the redis backend.
REDIS_KEY_PREFIX = "crudauth:rl:"

# Memory backend: run a full expired-key sweep once every N increments.
MEMORY_SWEEP_EVERY_INCREMENTS = 256
