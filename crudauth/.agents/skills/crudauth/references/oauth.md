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

`OAuthCredentials(client_id, client_secret="", scopes=None, issuer=None)`; leave `client_secret`
empty for a public (PKCE-only) client. Built-in providers: `"google"`, `"github"` (they self-register
on import, and raise at startup without a secret). `AuthUserMixin` includes `google_id` /
`github_id`; a custom shape needs `oauth=True`.

Any OIDC provider (Keycloak, Zitadel, Authentik, Auth0, Okta, Entra ID) needs no class — set
`issuer` and `GenericOIDCProvider` is used:

```python
oauth={"keycloak": OAuthCredentials(client_id=..., client_secret=...,
                                    issuer="https://sso.example.com/realms/main")}
```

The dict key is the provider name (`keycloak` -> `keycloak_id` column, `/oauth/keycloak/...`).
Endpoints come from `{issuer}/.well-known/openid-configuration` during `await auth.initialize()`,
so the lifespan call is required; the provider raises on first use if it was skipped. Startup
rejects a document declaring a different issuer, a non-https issuer (except localhost), or a
document missing an endpoint. Scopes default to `openid profile email`; client authentication
follows the document (`client_secret_post`, or Basic when that's all the provider accepts);
`email_verified` is used exactly as the provider states it. `GenericOIDCProvider.from_discovery(...)`
builds one outside `CRUDAuth`.

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
   - **no email / unverified email** → refused (`email_missing` / `email_unverified`). Linking and
     creating both require `info.email_verified`, the account-takeover defense.
   - **verified-email match** → links the provider to the existing account (`{provider}_id` set), so
     the user can then sign in by password or provider. If that account's own email was never
     verified, the link **claims** it: unusable password, MFA enrollment removed, `token_version`
     bumped, sessions signed out, email marked verified. An account already linked to another id of
     that provider is refused (`provider_already_linked`).
   - **otherwise** → a new user, created verified, with an unusable password and a unique username
     derived from the profile, cut to the `username` column's length (32 when unbounded), with `_1`,
     `_2`, ... then a random suffix on collision.

**The claim only works while `email_verified` is server-owned.** It's the whole defense against
someone registering under an address they don't control: the owner's provider login takes the
account back. A signup route the app wrote itself that accepts `email_verified` in its body lets an
attacker register as already verified, so the link finds a "verified" account, skips the claim, and
leaves their password working on the account the owner now signs into. Same for `google_id` /
`github_id`, which decide *which* account a login resolves to. If the app doesn't mount `/register`,
check its own schema: `auth.repo.gated_register_fields(SignUp.model_fields)` must be empty. See
`identity.md`.

**An app that links accounts itself** (its own routes over `OAuthAccountService` is fine; its own
linking code is not) has to claim too. Linking a provider id onto an account by email without
making the password unusable, bumping `token_version` and terminating sessions hands the account to
whoever registered the address first, whatever `email_verified` says.

A disabled user gets no session (`account_inactive`). Failures redirect to `redirect_base_url` with
`?error=<code>` (`oauth_failed`, `invalid_state`, `email_missing`, `email_unverified`,
`email_too_long`, `provider_already_linked`, `account_inactive`), or return `400 {"detail": "<code>"}`
in JSON mode — except `invalid_state`, which answers `400 {"detail": "Invalid or expired OAuth state"}`.
`invalid_state` means the callback's state didn't match the browser's cookie or is no longer stored.
The service raises `OAuthAccountException` (`.code`). `authorize` is rate limited per IP
(`oauth_authorize`, 30/hour).

## Provisioning OAuth users

`new_user_fields` / `new_user_defaults` run on the OAuth create path too. The callback's
`NewUserContext` has `email`, `username`, `source="oauth"`, the live `db`, and the provider profile, plus
`ctx.suggested_name` (provider display name, email local-part fallback; not truncated, so slice it for a
length-limited column):

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
credentials in `oauth={"name": OAuthCredentials(...)}` like a built-in. Set
`requires_client_secret = True` on a provider that never accepts a public client.
