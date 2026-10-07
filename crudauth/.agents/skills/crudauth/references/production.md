# Production: storage, lifespan, rate limiting, sudo

The dev defaults run in one process: state lives in memory and the limiter is in-process (cookies are
already `secure=True` unless you turned that off for local HTTP). Going to production is four changes; the auth config and the API don't change, only
*where state lives* and the operational wiring.

## 1. Move state to Redis

crudauth keeps server-side state (sessions, CSRF, lockout counters, single-use email/OAuth tokens) in
a pluggable store. In memory it isn't shared across workers/pods, which silently weakens lockout,
sessions, and one-time-token atomicity. Point crudauth at Redis once:

```python
REDIS_URL = os.environ["REDIS_URL"]
auth = CRUDAuth(..., redis_url=REDIS_URL)  # sessions, CSRF, tokens, OAuth state, lockout/throttles
```

- crudauth opens one client for the URL, shares it across every store, and closes it on shutdown.
  The Redis backends need Redis 7.0+ (or Valkey).
- `redis_client=` instead of `redis_url=` reuses an app-built async client (any `decode_responses`,
  `RedisCluster` included); crudauth never closes a client it didn't build.
- Configuring a part directly overrides the default for that part:
  `SessionTransport(redis_client=...)` or `SessionTransport(backend="memory")` for sessions/CSRF,
  `rate_limiter=redis_rate_limiter(client=...)` for counters.
- Keep auth state in its own Redis database, not the cache's: a flush or eviction logs users out.

crudauth logs a startup warning naming each part still in memory. Pass
`warn_on_memory_backend=False` only if you deliberately run a single worker.

### Or your own database (no Redis)

For several workers on PostgreSQL/MySQL/SQLite without Redis:
`CRUDAuth(..., database_store=DatabaseStore(async_sessionmaker(engine, expire_on_commit=False)))`.
Every store (sessions, CSRF, token/OAuth-state/MFA stores) and the default rate limiter move into
two tables, `crudauth_store` and `crudauth_counters` (renamable). Lockout counters must be shared
too, or N workers give N times the attempts, which is why one switch moves both. Create the tables
with `await store.create_tables()` or in a migration (`DatabaseStore(..., metadata=Base.metadata)`
lets Alembic autogenerate them). Every 1000 writes about as many expired rows are purged per table (`purge_every=`, `0`
to call `store.purge_expired()` yourself); a failed purge is logged, never raised.
Deadlocks (MySQL/MariaDB gap locks) are retried. MySQL needs 8.0.17+, MariaDB 10.2+. Not combinable with `redis_url`/`redis_client`.

## 2. Wire the lifespan

Redis backends open connections on startup. `initialize()` / `shutdown()` are required for Redis,
no-ops for in-memory:

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI

@asynccontextmanager
async def lifespan(app):
    await auth.initialize()
    yield
    await auth.shutdown()

app = FastAPI(lifespan=lifespan)
app.include_router(auth.router)
```

## 3. Secrets and cookies

- `SECRET_KEY` from the environment, never a literal. Rotating it invalidates every session and token.
- Session cookies are `secure=True` by default — serve over HTTPS. Don't set `CookieConfig(secure=False)`
  outside local dev. A session cookie may never be `SameSite=None`.

## 4. Behind a proxy

The socket peer is your load balancer, so IP-based throttles would see one client. Tell crudauth how
many trusted proxies sit in front so it reads the real client IP from `X-Forwarded-For`:

```python
auth = CRUDAuth(..., trusted_proxy_hops=1)   # default 0 ignores the header (correct when nothing is in front)
```

## Rate limiting & lockout

- The same escalating login-lockout policy is shared by `/login` and `/token`, keyed identically, so
  neither endpoint sidesteps the other's failure counter. It re-arms its round TTL atomically. Tune it
  with `CRUDAuth(lockout=LockoutConfig(...))` (from `crudauth.ratelimit`), which works for bearer-only
  apps too; `SessionTransport(login_*=...)` sets the same values, and setting both raises.
- Lockout keys case-fold the username and key IPv6 clients by `/64` (`client_ip_key`); `KeyBy.IP`
  does the same. A successful login under `on_login_success="clear_all"` only takes back the IP
  failures that username added, so it can't launder a spray.
- `rate_limits={...}` accepts only built-in actions (unknown keys raise); `RateLimit` rejects negative
  `times` and non-positive `seconds`.
- The limiter is a dumb counter port (`rate_limiter=`). Don't construct a backend inside a transport;
  pass it on `CRUDAuth`. Auth-adjacent endpoints carry a `rate_limit()` dependency or a service-level
  guard; per-target-email throttles fail silently (a 429 there would re-open the enumeration oracle).
- A custom backend implements the `RateLimiterBackend` port (the atomic counter surface) and goes in
  `rate_limiter=`.

## Sudo mode

For destructive actions, require fresh re-authentication:

```python
from crudauth import SudoConfig
auth = CRUDAuth(..., sudo=SudoConfig())

@app.post("/account/delete")
async def delete_account(_: Principal = Depends(auth.require_sudo())):
    ...
```

Sudo is short-lived, stamped on the session, has its own lockout, and fires an `on_after_sudo` hook.

## Custom storage backend

Implement the storage port (serialize Pydantic models under `{prefix}{id}` with per-key TTL, plus the
atomic `set_if_absent` / `get_and_delete` primitives the one-time-token flows need). A networked backend
must also override `modify` with a compare-and-set, since session activity, sudo and CSRF rotation write
the same record concurrently, and should implement `remove_from_user_index` if it keeps a per-user
index. The built-ins are in-memory and Redis. Hand a session store to the transport with
`SessionTransport(storage=..., csrf_storage=...)`.
