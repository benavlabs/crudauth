# Sign in with Google

This recipe adds a "Sign in with Google" button that bounces the user out to Google and brings them
back logged in, with the account either linked to an existing user or created fresh. The same shape
works for GitHub or a custom provider; Google is the example here.

It builds on the [email and password](email-password.md) base (a model, a session transport, a
mounted router) and a Google Cloud OAuth client.

## Before you start: a Google OAuth client

In the Google Cloud console, create an OAuth 2.0 Client ID of type "Web application". You'll get a
client ID and a client secret. Register the redirect URI CRUDAuth will use, which is always:

```
{redirect_base_url}/oauth/google/callback
```

So for `redirect_base_url="https://app.example.com"` that's
`https://app.example.com/oauth/google/callback`. Keep the client secret out of source, in your
environment.

## 1. The model

OAuth needs a per-provider id column to store and match the linked account (`google_id`,
`github_id`, ...). `AuthUserMixin` already includes the built-in ones, so the default model needs
nothing extra:

```python title="models.py"
from crudauth.models import AuthUserMixin
from myapp.db import Base

class User(Base, AuthUserMixin):
    __tablename__ = "users"
```

If you built a custom shape with `make_auth_identity`, keep `oauth=True` (the default) so the
provider columns are emitted.

## 2. Wire it up

OAuth establishes a session on the callback, so it requires a `SessionTransport` and a public
`redirect_base_url`. Pass each provider's credentials in `oauth={...}`:

```python title="main.py"
import os
from crudauth import CRUDAuth, OAuthCredentials, SessionTransport
from myapp.db import get_session
from myapp.models import User

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY=os.environ["SECRET_KEY"],
    redirect_base_url="https://app.example.com",
    transports=[SessionTransport()],
    oauth={
        "google": OAuthCredentials(
            client_id=os.environ["GOOGLE_CLIENT_ID"],
            client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
        ),
    },
)
app.include_router(auth.router)
```

This mounts two routes for the provider: `GET /oauth/google/authorize` (start the flow) and
`GET /oauth/google/callback` (finish it).

## 3. The button

Your "Sign in with Google" link just points at the authorize route. Add `redirect_to` to say where
the user lands after login (same-origin relative paths only):

```html
<a href="/oauth/google/authorize?redirect_to=/dashboard">Sign in with Google</a>
```

That's the whole frontend. CRUDAuth redirects to Google, Google signs the user in, and the callback
returns to your app and establishes the session.

## 4. What happens on the callback

CRUDAuth runs the authorization-code flow, then finds or creates the user:

- **Link:** if a user already exists with Google's verified email, the Google account is linked to
  it (`google_id` is set), and that user can sign in by password or by Google afterward.
- **Create:** otherwise a new user is created from the Google profile, with `email_verified` taken
  from Google, so a Google user usually arrives already verified.

## 5. Set your own columns on new OAuth users

A new OAuth user comes from the provider profile, which won't carry your app's columns (a tier, a
display name). `new_user_fields` and `new_user_defaults` run on the OAuth create path too, so you
set them once and cover both password signup and OAuth:

```python
auth = CRUDAuth(
    ...,
    new_user_defaults={"tier": "free"},
    new_user_fields=lambda ctx: {"display_name": ctx.email.split("@")[0]},
)
```

See [Registration](../guides/accounts/registration.md#setting-columns-the-server-controls) for the
full provisioning story.

## 6. After login

The callback establishes a normal session, so everything downstream is identical to a password
login: the session cookie and CSRF, `/me`, and your `current_user()` gates all behave the same. A
Google-created user has no password until they set one, so if you want them to be able to log in by
password as well, offer a "set a password" flow (a password reset request does it).

## What makes this safe

Two defenses you didn't write carry this flow, both on by default. The `state` is bound to the
browser that started the login (a short-lived cookie the callback must match), so a captured or
forged callback can't be replayed into someone else's session, and the post-login redirect is
validated as a same-origin relative path so it can't become an open redirect. The one worth
internalizing: CRUDAuth links a provider to an existing account *only* when the provider reports a
verified email. An unverified, attacker-influenceable address can never claim an account it doesn't
own; it is refused and routed to manual linking. Creating a *new* account on an unverified email is
fine (there is nothing to hijack), and that row stays `email_verified=False` until proven. Linking
is the asymmetric case, and that asymmetry is the whole defense.

## Where to go next

- **GitHub** is the same shape: add `"github": OAuthCredentials(...)` (the mixin already has a
  `github_id` column) and point a button at `/oauth/github/authorize`.
- **A custom provider:** implement the provider port and register it, then pass its credentials like
  the built-ins. See the [OAuth reference](../api/oauth.md).
- The full OAuth feature guide, with the flow diagram and the security details: [OAuth](../guides/auth/oauth.md).
