# Authentication

How to authenticate requests and authorize them, whichever transport the caller uses. Every
transport resolves to the same [`Principal`](../../api/principal.md), so your authorization
code never depends on how the request arrived.

<div class="grid cards" markdown>

-   **Protecting routes**

    ---

    Gate endpoints with `current_user()` and its keyword guards (superuser, scopes,
    verified, and custom checks).

    [Protecting routes →](protecting-routes.md)

-   **Sessions**

    ---

    Cookie auth, CSRF, remember-me, multi-device management, and the session lifecycle.

    [Sessions →](sessions.md)

-   **Bearer tokens**

    ---

    JWT access and refresh tokens, scopes, and revocation.

    [Bearer tokens →](bearer.md)

-   **Multiple transports**

    ---

    Run sessions and bearer together behind one `Principal`.

    [Multiple transports →](multiple-transports.md)

-   **OAuth**

    ---

    Google, GitHub, and custom providers.

    [OAuth →](oauth.md)

-   **Sudo mode**

    ---

    Short-lived re-authentication for sensitive actions.

    [Sudo mode →](sudo.md)

</div>

## Where to start

!!! tip "Not sure which to read first?"

    **New to CRUDAuth?** [Protecting routes](protecting-routes.md) covers the one dependency
    you'll use everywhere.

    **Browser app?** [Sessions](sessions.md) is the default and needs no configuration.

    **API, mobile, or CLI?** [Bearer tokens](bearer.md).

    **Supporting both at once?** [Multiple transports](multiple-transports.md).

    **Adding social login?** [OAuth](oauth.md). **Gating destructive actions?**
    [Sudo mode](sudo.md).

[Start with Protecting routes →](protecting-routes.md){ .md-button .md-button--primary }
