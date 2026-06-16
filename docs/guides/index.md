# Guides

Task-oriented how-tos for the things you'll actually do with crudauth. Each guide is
self-contained, shows the setup that produces the endpoints, and links into the
[API Reference](../api/index.md) for the details.

<div class="grid cards" markdown>

-   **Authentication**

    ---

    Protect routes, run cookie sessions and bearer tokens, add OAuth, and gate sensitive
    actions with sudo.

    [Authentication →](auth/index.md)

-   **Accounts**

    ---

    Registration, email verify / reset / change, passwords, and device & session
    management.

    [Accounts →](accounts/index.md)

-   **Infrastructure**

    ---

    Storage and lifespan, rate limiting and lockout, and lifecycle hooks.

    [Infrastructure →](infra/index.md)

</div>

## Where to start

!!! tip "Pick the guide that matches what you're building"

    **A web app (server-rendered or SPA)?** Start with [Sessions](auth/sessions.md), then
    [Protecting routes](auth/protecting-routes.md).

    **An API, mobile app, or CLI?** Start with [Bearer tokens](auth/bearer.md).

    **Both a web app and an API?** See [Multiple transports](auth/multiple-transports.md);
    they share one identity.

    **Social login?** See [OAuth](auth/oauth.md).

    **Sign-up, email verification, or password reset?** See the [Accounts](accounts/index.md)
    group.

Every capability is additive. Start with the default session setup and add transports, OAuth,
and email flows as you need them, without rewriting how your routes authorize.

[Start with Protecting routes →](auth/protecting-routes.md){ .md-button .md-button--primary }
