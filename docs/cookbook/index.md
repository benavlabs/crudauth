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

</div>

**Prerequisites:** a FastAPI app and an async SQLAlchemy 2.0 session dependency. Each recipe
shows everything else from scratch.
