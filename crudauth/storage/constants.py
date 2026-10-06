"""Constants for the storage backends."""

from __future__ import annotations

# Backend selectors accepted by ``get_session_storage``.
BACKEND_MEMORY = "memory"
BACKEND_REDIS = "redis"
# Sessions held in a store the app passed to SessionTransport(storage=...).
BACKEND_CUSTOM = "custom"

# Default key namespace prefix for stored values.
DEFAULT_STORAGE_PREFIX = "session:"

# Suffix appended to the prefix root for the per-user session index (redis).
USER_INDEX_SUFFIX = "_users:"

# Fallback connection URL when none is supplied to the redis backend.
DEFAULT_REDIS_URL = "redis://localhost:6379/0"

# Run a full expired-key sweep once every N writes (memory backend).
MEMORY_SWEEP_EVERY_WRITES = 256
