# Cookbook

Complete, from-scratch recipes for a goal. Where the [Guides](../guides/index.md) document one
feature at a time and assume the base setup, each recipe here builds a working setup end to end,
so you can copy one and have the account shape you want.

<div class="grid cards" markdown>

-   **[Email + password](email-password.md)**

    ---

    The default shape: email/username login, password, verification, and reset, wired end to end.

    [Read →](email-password.md)

-   **[Username-only accounts](username-only.md)**

    ---

    No email anywhere: log in by username, no recovery, no verification. For throwaway or
    internal accounts.

    [Read →](username-only.md)

-   **[Phone recovery (SMS)](phone-recovery.md)**

    ---

    Phone-first accounts: log in by username, verify and reset over SMS through your own
    delivery channel.

    [Read →](phone-recovery.md)

-   **[Sign in with Google](sign-in-with-google.md)**

    ---

    Add OAuth end to end: the button, the callback, account linking on verified email, and
    provisioning new users.

    [Read →](sign-in-with-google.md)

-   **[Email, password, and Google](email-password-and-google.md)**

    ---

    Both doors, one account: how a password signup and a Google sign-in link into the same
    user, safely.

    [Read →](email-password-and-google.md)

-   **[A token API (bearer)](token-api.md)**

    ---

    For mobile, CLI, and SPA clients: JWT access tokens, refresh, and scopes, no cookies or
    CSRF.

    [Read →](token-api.md)

-   **[Web and API in one backend](web-and-api.md)**

    ---

    Cookie sessions and bearer tokens together, both resolving to one Principal your routes
    gate on.

    [Read →](web-and-api.md)

-   **[Server-set fields at signup](server-set-fields.md)**

    ---

    Tiers, org ids, derived names: who sets a column at signup, and why the server-set ones
    can't be forged.

    [Read →](server-set-fields.md)

-   **[Onboard an existing users table](existing-users-table.md)**

    ---

    Adopt CRUDAuth on a table you already have, mapping your column names instead of renaming
    your schema.

    [Read →](existing-users-table.md)

-   **[Going to production](going-to-production.md)**

    ---

    Redis-backed shared state, lifespan wiring, secrets from the environment, secure cookies,
    and the real client IP behind a proxy.

    [Read →](going-to-production.md)

</div>

**Prerequisites:** a FastAPI app and an async SQLAlchemy 2.0 session dependency. Each recipe
shows everything else from scratch.
