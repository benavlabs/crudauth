# Email, password, and Google

This is the shape most consumer apps actually ship: users can sign up with an email and a password
*or* with Google, and it's one account either way. The two base recipes already cover each door on
its own. This one is about what happens where they meet: how a password account and a Google sign-in
become a single user instead of two.

It assumes you've seen [email and password](email-password.md) (the model, the `EmailSender`) and
[Sign in with Google](sign-in-with-google.md) (the OAuth client and wiring). Here we just turn both
on at once and focus on linking.

## 1. One config, both doors

The default `AuthUserMixin` already has everything for both paths: email and username login, a
password, and the `google_id` column OAuth needs. Turn on `email=` and `oauth=` together, with a
session transport and a public base URL:

```python title="main.py"
import os
from crudauth import CRUDAuth, EmailConfig, OAuthCredentials, SessionTransport
from myapp.db import get_session
from myapp.models import User          # class User(Base, AuthUserMixin)
from myapp.email import MySender       # your EmailSender, from the email recipe

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY=os.environ["SECRET_KEY"],
    redirect_base_url="https://app.example.com",
    transports=[SessionTransport()],
    email=EmailConfig(sender=MySender(), frontend_url="https://app.example.com"),
    oauth={
        "google": OAuthCredentials(
            client_id=os.environ["GOOGLE_CLIENT_ID"],
            client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
        ),
    },
)
app.include_router(auth.router)
```

That mounts both front doors: the password door (`/register`, `/login`, plus verify and reset) and
the Google door (`/oauth/google/authorize` and its callback). Both end at the same kind of session
and resolve to the same `Principal`, so your `current_user()` gates never care which door a request
came through.

## 2. Linking: password first, then Google

Alice registers with `alice@example.com` and a password. Weeks later she clicks "Sign in with
Google" using that same Google account. Because Google reports the email as verified, CRUDAuth finds
her existing row by email and **links** the Google account to it (sets `google_id`) rather than
creating a second account. From then on she can use either door, and both land on the same user.

There is nothing to wire for this; finding-or-linking is what the callback does. The only thing you
provide is that the two identities share an email address.

## 3. Linking: Google first, then a password

Bob comes in through Google first. He gets an account with no usable password (and, because Google
verified his address, `email_verified=True`). To let him *also* log in by password later, give him a
"set a password" affordance, which is just the existing password-reset flow:

```bash
curl -X POST http://localhost:8000/password/reset-request \
  -H "Content-Type: application/json" -d '{"email":"bob@example.com"}'
# Bob clicks the emailed link; your page posts the token + the password he chose:
curl -X POST http://localhost:8000/password/reset-confirm \
  -H "Content-Type: application/json" \
  -d '{"token":"eyJ...","new_password":"a-strong-one"}'
```

After that, both doors work for Bob too. "Set a password" and "reset a password" are the same
endpoint; a Google-first user simply has no password to begin with.

## 4. The rule that keeps linking safe

The reason this coexistence is not an account-takeover hole: CRUDAuth links a provider to an
existing account **only when the provider reports a verified email**. If someone points a Google
account with an *unverified* `alice@example.com` at the callback, it does not link to Alice; it is
refused with "sign in with your existing method to link this provider." An attacker can't attach
their Google login to your account using an address they haven't proven they control. Linking is the
one asymmetric operation (it touches an account the OAuth user may not own), and CRUDAuth treats it
that way by default.

## 5. Who has to verify their email

The two doors arrive in different states, and the `verified` gate handles both uniformly:

- A **Google** user usually arrives `email_verified=True` (Google verified the address), so they skip
  your verification flow.
- A **password** user is `email_verified=False` until they go through verify-request / verify-confirm.

`current_user(verified=True)` reads that one flag regardless of how the user signed up, so a route
that needs a proven email treats both doors the same.

## Where to go next

- Add **GitHub** beside Google: one more entry in `oauth={...}` and a button at
  `/oauth/github/authorize` (the mixin already has `github_id`).
- Set app columns on either signup path: [server-controlled fields](../guides/accounts/registration.md#setting-columns-the-server-controls)
  run on both password and OAuth creates.
- The single-door versions: [email and password](email-password.md), [Sign in with Google](sign-in-with-google.md).
