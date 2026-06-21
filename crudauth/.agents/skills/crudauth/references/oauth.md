# OAuth

crudauth runs the authorization-code flow, links the result to a user, and establishes a session on
the callback. It requires a `SessionTransport`, a public `redirect_base_url`, and a `{provider}_id`
column on the model.

## Setup

```python
from crudauth import CRUDAuth, OAuthCredentials, SessionTransport

auth = CRUDAuth(
    ..., transports=[SessionTransport()],
    redirect_base_url="https://app.example.com",
    oauth={
        "google": OAuthCredentials(client_id=..., client_secret=...),
        "github": OAuthCredentials(client_id=..., client_secret=...),
    },
)
```

`OAuthCredentials(client_id, client_secret, scopes=None)`. Built-in providers: `"google"`, `"github"`
(they self-register on import). `AuthUserMixin` includes `google_id` / `github_id`; a custom shape
needs `oauth=True`.

## Endpoints and the button

Each provider adds `GET /oauth/{provider}/authorize` and `GET /oauth/{provider}/callback`. Register
`{redirect_base_url}/oauth/{provider}/callback` as the provider's redirect URI. The frontend is one
link:

```html
<a href="/oauth/google/authorize?redirect_to=/dashboard">Sign in with Google</a>
```

`redirect_to` is where the callback sends the browser after login — **same-origin relative paths
only** (open-redirect hardened).

## The callback: link or create

1. The flow is CSRF-hardened: `state` is bound to the initiating browser via a short-lived cookie the
   callback must match, so a captured/forged callback can't complete someone else's login.
2. Then crudauth finds or creates the user, in order:
   - **provider id hit** → that user (returning login).
   - **verified-email match** → links the provider to the existing account (`{provider}_id` set), so
     the user can then sign in by password or provider. **Linking requires `info.email_verified`** — an
     unverified provider email matching an existing account is refused ("sign in with your existing
     method to link"), the account-takeover defense.
   - **otherwise** → a new user, created with `email_verified` taken from the provider (a Google user
     usually arrives verified), an unusable password, and a unique username derived from the profile.

## Provisioning OAuth users

`new_user_fields` / `new_user_defaults` run on the OAuth create path too. The callback's
`NewUserContext` has `email`, `username`, `source="oauth"`, the live `db`, and the provider profile, plus
`ctx.suggested_name` (provider display name, email local-part fallback):

```python
auth = CRUDAuth(..., new_user_defaults={"tier": "free"},
                new_user_fields=lambda ctx: {"display_name": ctx.suggested_name})
```

## Password for an OAuth-only account

An OAuth-created user has no usable password. `POST /set-password` lets an authenticated OAuth-only
account set a first password; alternatively the password-reset flow doubles as "set a password". After
that, both doors work.

## Custom provider

Implement the `AbstractOAuthProvider` port (`provider.py`: pass the three endpoints + scopes +
`provider_name`, implement `process_user_info(raw) -> OAuthUserInfo`, set `email_verified` honestly),
register it with `OAuthProviderFactory.register_provider("name", YourProvider)`, then pass its
credentials in `oauth={"name": OAuthCredentials(...)}` like a built-in.
