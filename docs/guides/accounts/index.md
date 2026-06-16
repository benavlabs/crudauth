# Accounts

Creating accounts, verifying and changing emails, handling passwords, and managing a user's
sessions. Each guide shows the setup that enables the routes, then how to use them.

<div class="grid cards" markdown>

-   **Registration**

    ---

    `POST /register`, the allowlist that keeps model columns from being mass-assigned, and
    custom request schemas.

    [Registration →](registration.md)

-   **Email flows**

    ---

    Verify, reset, and change-email with signed single-use tokens, over your own
    `EmailSender`.

    [Email flows →](email.md)

-   **Passwords**

    ---

    How passwords are stored, setting one on an OAuth-only account, and resetting a
    forgotten one.

    [Passwords →](passwords.md)

-   **Devices & sessions**

    ---

    List a user's active sessions, revoke one, or sign out everywhere.

    [Devices & sessions →](session-management.md)

</div>

## Where to start

!!! tip "Pick the task you're tackling"

    **Letting users sign up?** [Registration](registration.md) (it also shows the base setup
    that produces the auth routes).

    **Verifying emails or resetting forgotten passwords?** [Email flows](email.md).

    **OAuth users who need a password too?** [Passwords](passwords.md).

    **A "manage devices" or "sign out everywhere" screen?**
    [Devices & sessions](session-management.md).

[Start with Registration →](registration.md){ .md-button .md-button--primary }
