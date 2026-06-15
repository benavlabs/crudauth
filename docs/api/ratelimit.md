# Rate limiting & lockout

Per-endpoint throttling (`auth.rate_limit(...)`) and escalating login lockout, both over a
pluggable backend. Use `redis_rate_limiter(...)` in production.

::: crudauth.ratelimit.RateLimit

::: crudauth.ratelimit.KeyBy

::: crudauth.ratelimit.LockoutPolicy

::: crudauth.ratelimit.RateLimiterBackend

::: crudauth.ratelimit.MemoryRateLimiterBackend

::: crudauth.ratelimit.redis_rate_limiter
