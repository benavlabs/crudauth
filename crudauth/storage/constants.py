"""Constants for the storage backends."""

from __future__ import annotations

# Backend selectors accepted by ``get_session_storage``.
BACKEND_MEMORY = "memory"
BACKEND_REDIS = "redis"
BACKEND_DATABASE = "database"
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

# Default table names for the database backend; prefixed so they don't collide with app tables.
DEFAULT_STORE_TABLE = "crudauth_store"
DEFAULT_COUNTER_TABLE = "crudauth_counters"

# Longest key the database backend stores (an indexed VARCHAR fits MySQL's index limit).
# A longer one is stored as its start, this separator and a SHA-256 of the whole key.
DATABASE_KEY_MAX_LENGTH = 255
DATABASE_KEY_DIGEST_SEPARATOR = "#"

# Delete expired rows once every N writes from one database-backed store or limiter.
DATABASE_PURGE_EVERY_WRITES = 1000

# Rows deleted per statement when purging expired ones.
DATABASE_PURGE_BATCH_SIZE = 500
# Attempts at a transaction the database rolled back over a deadlock or lock timeout.
DATABASE_TRANSACTION_ATTEMPTS = 5

# Compare-and-set attempts before a database-backed modify gives up.
DATABASE_MODIFY_MAX_ATTEMPTS = 50
