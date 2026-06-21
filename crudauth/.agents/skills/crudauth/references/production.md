# Production: storage, lifespan, rate limiting, sudo

The dev defaults run in one process: state lives in memory, the limiter is in-process, cookies work
over plain HTTP. Going to production is four changes; the auth config and the API don't change, only
*where state lives* and the operational wiring.

## 1. Move state to Redis

crudauth keeps server-side state (sessions, CSRF, lockout counters, single-use email/OAuth tokens) in
a pluggable store. In memory it isn't shared across workers/pods, which silently weakens lockout,
sessions, and one-time-token atomicity. Point both stores at Redis:

```python
from crudauth import CRUDAuth, SessionTransport
from crudauth.ratelimit import redis_rate_limiter

REDIS_URL = os.environ["REDIS_URL"]
auth = CRUDAuth(
    ..., transports=[SessionTransport(backend="redis", redis_url=REDIS_URL)],
    rate_limiter=redis_rate_limiter(REDIS_URL),
)
```

crudauth logs a startup warning whenever an in-memory backend is active. Pass
`warn_on_memory_backend=False` only if you deliberately run a single worker.

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
  neither endpoint sidesteps the other's failure counter. It re-arms its round TTL atomically.
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
atomic `set_if_absent` / `get_and_delete` primitives the one-time-token flows need). The built-ins are
in-memory and Redis.
