# Infrastructure

The pieces that sit under the auth flows: where server-side state is stored, how you throttle
and lock out abuse, and where your app-specific side effects attach.

<div class="grid cards" markdown>

-   **Storage & lifespan**

    ---

    In-memory for dev, Redis for production, for sessions, CSRF, lockout, and one-time
    tokens. Plus the `initialize()` / `shutdown()` lifespan.

    [Storage & lifespan →](storage.md)

-   **Rate limiting & lockout**

    ---

    Throttle any route with `rate_limit()`, and the escalating login lockout built into the
    auth flows.

    [Rate limiting & lockout →](rate-limiting.md)

-   **Hooks**

    ---

    `AuthHooks` callbacks for welcome emails, trial grants, and audit logging, fired across
    every auth path.

    [Hooks →](hooks.md)

</div>

## Where to start

!!! tip "Pick the concern you're handling"

    **Going to production?** Start with [Storage & lifespan](storage.md) and move state to
    Redis.

    **Protecting an endpoint from abuse, or tuning login lockout?**
    [Rate limiting & lockout](rate-limiting.md).

    **Running side effects (welcome email, audit log) on auth events?** [Hooks](hooks.md).

[Start with Storage & lifespan →](storage.md){ .md-button .md-button--primary }
