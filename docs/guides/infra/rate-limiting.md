# Rate limiting & lockout

Two related protections: a general-purpose per-endpoint rate limiter you attach to any route,
and an escalating login lockout that's built into the auth flows. Both run over the same
[rate-limiter backend](storage.md) (in-memory by default, Redis in production).

## Throttling a route

`auth.rate_limit(action, limit, key=...)` builds a dependency you add to any endpoint:

```python
from fastapi import Depends
from crudauth.ratelimit import RateLimit, KeyBy

@app.post("/contact", dependencies=[Depends(auth.rate_limit("contact", RateLimit(5, 60)))])
async def contact(...):
    ...
```

`RateLimit(times, seconds)` is the budget (5 per 60s above). Key it by client IP (the
default), by authenticated user (`key=KeyBy.USER`), or by a function of the request. It writes
`X-RateLimit-*` headers and raises a `RateLimitException` (`429` with `Retry-After`) when the
caller is over budget.

The built-in account actions (`register`, the email/password requests) ship with defaults.
Override them per action with `rate_limits={...}` on `CRUDAuth`:

```python
auth = CRUDAuth(..., rate_limits={"register": RateLimit(3, 600)})  # 3 signups / 10 min per IP
```

## Login lockout

<p align="center">
  <img src="../../assets/diagrams/lockout-light.png#only-light" alt="After 5 failed attempts per IP and username, the first lockout is 60s, the next 120s, the next 240s, doubling each round up to a maximum; a successful login clears the counters" width="100%">
  <img src="../../assets/diagrams/lockout-dark.png#only-dark" alt="After 5 failed attempts per IP and username, the first lockout is 60s, the next 120s, the next 240s, doubling each round up to a maximum; a successful login clears the counters" width="100%">
</p>

The login path (the session `/login` and the bearer `/token`, which share it) has its own
escalating lockout, separate from `rate_limit()`. Repeated failures from an IP + username
trip a block whose duration doubles each round, up to a cap. Configure it on the
`SessionTransport`:

```python
SessionTransport(
    login_max_attempts=5,            # failures allowed in the window
    login_attempt_window_seconds=60,
    login_lockout_base_seconds=60,   # first lockout; doubles each round
    login_lockout_max_seconds=3600,  # cap
    on_login_success="clear_all",
)
```

- **Escalation:** each repeat offense waits longer (60s, 120s, 240s, ... up to the cap), and
  the round count persists so a slow, paced attack keeps climbing rather than resetting.
- **`on_login_success`:** `"clear_all"` (default) clears both per-user and per-IP pressure on
  a good login, which is friendly to users behind shared egress; `"clear_user_only"` keeps
  per-IP pressure, which is tighter but only safe when your per-IP key identifies one client.
- **Keying behind a proxy:** per-IP counters use the client IP, so set `trusted_proxy_hops` to
  the number of proxies in front of you. Otherwise every request looks like the proxy's IP and
  shares one bucket. See [`get_client_ip`](../../api/utils.md).

Lockout **fails closed**: if the limiter backend errors, a login is blocked rather than
allowed, so an attacker can't disable it by knocking the backend over.

---

[Next: Hooks →](hooks.md){ .md-button .md-button--primary }
