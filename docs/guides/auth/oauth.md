# OAuth

OAuth lets users sign in with Google, GitHub, or a custom provider. crudauth runs the
authorization-code flow, links the result to a user in your database, and establishes a
session on the callback.

```python
from crudauth import CRUDAuth, SessionTransport, OAuthCredentials

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    redirect_base_url="https://app.example.com",
    transports=[SessionTransport()],
    oauth={
        "google": OAuthCredentials(client_id="...", client_secret="..."),
        "github": OAuthCredentials(client_id="...", client_secret="..."),
    },
)
```

OAuth establishes a session on the callback, so it requires a `SessionTransport` and a
`redirect_base_url`. Each provider also needs a `{provider}_id` column on your user model
(`google_id`, `github_id`, ...) to store and match the account; `AuthUserMixin` includes the
built-in ones.

This adds two routes per provider: `GET /oauth/{provider}/authorize` (start the flow) and
`GET /oauth/{provider}/callback` (finish it). The redirect URI you register with the provider
is `{redirect_base_url}/oauth/{provider}/callback`.

## The flow

<p align="center">
  <img src="../../assets/diagrams/oauth-flow-light.png#only-light" alt="The four-step OAuth authorization-code flow: your app redirects out with a state, the provider signs the user in, the callback returns a code and state which crudauth rechecks, then crudauth exchanges the code, links the user, and logs them in" width="100%">
  <img src="../../assets/diagrams/oauth-flow-dark.png#only-dark" alt="The four-step OAuth authorization-code flow: your app redirects out with a state, the provider signs the user in, the callback returns a code and state which crudauth rechecks, then crudauth exchanges the code, links the user, and logs them in" width="100%">
</p>

crudauth binds the `state` parameter to the initiating browser via a cookie, so a stolen or
forged callback can't complete someone else's login. The redirect target after login is
validated against an allowlist to prevent open redirects.

## Account linking

On a successful callback, crudauth finds or creates the user:

- If a user already exists with the provider's verified email, the provider account is linked
  to it (the `{provider}_id` column is set). The user can then sign in by password or by that
  provider.
- Otherwise a new user is created from the provider profile.

## Custom providers

Add a provider by implementing the `AbstractOAuthProvider` port and registering it with
`OAuthProviderFactory`, then pass its credentials in `oauth={...}` like the built-ins. See
the [OAuth reference](../../api/oauth.md) for the port and factory.

---

[Next: Sudo mode →](sudo.md){ .md-button .md-button--primary }
