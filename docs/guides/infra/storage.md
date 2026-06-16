# Storage & lifespan

crudauth keeps server-side state in a pluggable store: sessions, CSRF tokens, login-lockout
counters, and single-use email and OAuth tokens. In-memory is the zero-config default and
fine for development; Redis is what you want in production.

<p align="center">
  <img src="../../assets/diagrams/backends-light.png#only-light" alt="In-memory state lives in the process and is not shared across workers; Redis holds the same state shared across all workers and across restarts; the API is identical either way" width="100%">
  <img src="../../assets/diagrams/backends-dark.png#only-dark" alt="In-memory state lives in the process and is not shared across workers; Redis holds the same state shared across all workers and across restarts; the API is identical either way" width="100%">
</p>

## In-memory (default)

Nothing to configure. The catch: state lives in the process, so under multiple workers
(`uvicorn --workers 4`, gunicorn, several pods) it isn't shared. That silently weakens
lockout counters, sessions, and one-time-token atomicity. crudauth logs a startup warning
whenever an in-memory backend is active. Use it for development, tests, and single-worker
deployments.

## Redis (production)

Point both the session store and the rate limiter at Redis:

```python
from crudauth import CRUDAuth, SessionTransport
from crudauth.ratelimit import redis_rate_limiter

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    transports=[SessionTransport(backend="redis", redis_url="redis://localhost:6379")],
    rate_limiter=redis_rate_limiter("redis://localhost:6379"),
)
```

`SessionTransport(backend="redis")` moves sessions, CSRF, and the one-time-token / OAuth-state
stores to Redis; `redis_rate_limiter(...)` moves the lockout and throttle counters. Once
you've deliberately accepted in-memory on a single worker, pass `warn_on_memory_backend=False`
to silence the warning.

## Lifespan

Server-side backends open connections on startup, so call `initialize()` and `shutdown()`
from your app's lifespan. It's required for Redis and a no-op for in-memory.

```python
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app):
    await auth.initialize()
    yield
    await auth.shutdown()

app = FastAPI(lifespan=lifespan)
```

---

[Next: Rate limiting & lockout →](rate-limiting.md){ .md-button .md-button--primary }
