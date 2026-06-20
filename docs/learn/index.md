# Learn CRUDAuth

Most auth bugs aren't exotic; they come from wiring together pieces you don't fully
understand: a cookie here, a token there, a password hash you hope is right. This track takes
the opposite approach: it builds the mental model first, then assembles a real CRUDAuth setup
on top of it, so the code you ship is code you actually understand.

It runs in three acts:

- **Understand** (0–1): how the web carries identity, and the handful of ways that goes wrong.
- **Build** (2–7): a working setup, added one need at a time, from a single gated route up to
  OAuth and email flows.
- **Ship** (8–9): the hardening and infrastructure that separate a localhost demo from
  something you'd put real users behind.

Read it in order if auth is new to you. The first two chapters have almost no
crudauth-specific code, and everything after leans on them. If you already know sessions,
tokens, and CSRF, skim 0–1 and start building at chapter 2; if you just want the two-minute
setup, that's [Getting started](../getting-started.md).

<div class="grid cards" markdown>

-   **[0. How web auth works](0-how-web-auth-works.md)**

    ---

    HTTP forgets you between requests, so identity has to travel with each one. Sessions vs
    tokens, why cookies pull in CSRF, how passwords are stored, and what a `Principal` is.

    [Start here →](0-how-web-auth-works.md)

-   **[1. How auth goes wrong](1-how-auth-goes-wrong.md)**

    ---

    The threat model in plain terms: user enumeration, brute force, CSRF, token theft, mass
    assignment at signup, and timing leaks.

    [Read →](1-how-auth-goes-wrong.md)

-   **[2. Your first protected route](2-your-first-protected-route.md)**

    ---

    Configure `CRUDAuth`, mount the router, register and log in, gate an endpoint, and meet the
    `Principal` that every later chapter returns to.

    [Read →](2-your-first-protected-route.md)

-   **[3. Modeling your user](3-modeling-your-user.md)**

    ---

    `AuthUserMixin`, the logical-field contract, mapping onto a table you already have, and
    which fields registration may set.

    [Read →](3-modeling-your-user.md)

-   **4. Sessions, cookies, and CSRF**

    ---

    The default transport up close: the server-side session, the synchronizer-token check,
    remember-me, and managing a user's devices. *(Coming soon)*

-   **5. An API for your app**

    ---

    When a mobile or SPA client needs tokens: access vs refresh, scopes, and how a second
    transport still resolves to one `Principal`. *(Coming soon)*

-   **6. Sign in with Google**

    ---

    The OAuth authorization-code flow, binding `state` to the browser, linking provider
    accounts, and adding your own provider. *(Coming soon)*

-   **7. Emails: verify, reset, change**

    ---

    The account lifecycle: the `EmailSender` port, signed single-use tokens, and the
    request/confirm cycle. *(Coming soon)*

-   **8. Hardening before you ship**

    ---

    Lockout, trusted-proxy IPs, and sudo for sensitive actions, plus what CRUDAuth already
    does for you. Closes the loop with chapter 1. *(Coming soon)*

-   **9. Going to production**

    ---

    Moving state to Redis, the lifespan, the multi-worker reality, and a short deploy
    checklist. *(Coming soon)*

</div>

**Prerequisites:** comfort with FastAPI routes and `Depends`, and async SQLAlchemy 2.0
models. No prior experience with auth internals, OAuth, or JWTs; that's what this is for.

[Start: How web auth works →](0-how-web-auth-works.md){ .md-button .md-button--primary }
