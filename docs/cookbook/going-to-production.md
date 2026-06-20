# Going to production

The dev defaults are tuned for one process: state lives in memory, the rate limiter is in-process,
and cookies are configured to work over plain HTTP. None of that survives more than one worker.
Going to production is four changes, and the security model and the API stay identical, what moves
is *where state lives* and the operational wiring around it.

This builds on any of the earlier recipes; the auth config itself doesn't change.

## 1. Move state to Redis

CRUDAuth keeps server-side state (sessions, CSRF tokens, lockout counters, single-use email and
OAuth tokens) in a pluggable store. In memory, that state lives in the process, so under multiple
workers or pods it isn't shared, which silently weakens lockout counters, sessions, and the
atomicity of one-time tokens. Point both the session store and the rate limiter at Redis:

```python title="main.py"
from crudauth import CRUDAuth, SessionTransport
from crudauth.ratelimit import redis_rate_limiter

REDIS_URL = os.environ["REDIS_URL"]

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY=os.environ["SECRET_KEY"],
    transports=[SessionTransport(backend="redis", redis_url=REDIS_URL)],
    rate_limiter=redis_rate_limiter(REDIS_URL),
)
```

`SessionTransport(backend="redis")` moves sessions, CSRF, and the one-time-token and OAuth-state
stores to Redis; `redis_rate_limiter(...)` moves the lockout and throttle counters. CRUDAuth logs a
startup warning whenever an in-memory backend is active, so a multi-worker deploy left on the
default won't fail silently; if you've *deliberately* chosen in-memory on a single worker, pass
`warn_on_memory_backend=False`.

## 2. Wire the lifespan

Redis backends open connections on startup, so call `initialize()` and `shutdown()` from your app's
lifespan (it's required for Redis and a no-op for in-memory):

```python title="main.py"
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

Two things the dev recipes glossed over:

- **The secret comes from the environment**, never a literal. `SECRET_KEY` signs every session and
  token; rotating it invalidates them all, so treat it like any other production secret.
- **Cookies are secure by default.** `CookieConfig.secure` is `True` unless you turned it off, so
  serve over HTTPS and the session cookie is sent only over TLS. The dev recipes used
  `CookieConfig(secure=False)` to work on `http://localhost`; drop that in production. Don't ship
  `secure=False`.

## 4. Behind a load balancer

If you run behind a reverse proxy or load balancer, the socket peer is the proxy, not the user, so
IP-based throttles would see every request as one client. Tell CRUDAuth how many trusted proxies sit
in front so it reads the real client IP from `X-Forwarded-For`:

```python
auth = CRUDAuth(..., trusted_proxy_hops=1)   # one proxy/LB in front
```

Set it to the actual number of hops you control; the default `0` ignores the header and uses the
socket peer (correct when nothing is in front, safe when you're unsure).

## What production actually changes

Notice what didn't change: not the routes, not the gates, not a line of your authorization code. The
API is identical to development. What changed is that state is now *shared and durable* (Redis), so
lockout counters, sessions, and one-time-token atomicity actually hold across every worker and
across restarts, and the operational edges are wired (lifespan connections, secrets from the
environment, TLS-only cookies, the real client IP). CRUDAuth makes the one dangerous default loud
rather than silent: it warns when a memory backend is active, so the multi-worker footgun announces
itself instead of quietly degrading your security.

## Where to go next

- The backends in depth: [Storage & lifespan](../guides/infra/storage.md).
- Tuning the limits: [Rate limiting & lockout](../guides/infra/rate-limiting.md).
- Back to the recipes: the [cookbook index](index.md).
