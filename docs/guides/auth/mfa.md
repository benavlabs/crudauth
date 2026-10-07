# Two-factor authentication

MFA adds a second step to login: after the password, the user types the six-digit code from an
authenticator app (Google Authenticator, 1Password, Authy, ...). A stolen password alone no longer
gets a session or a token.

It's opt-in. Install the extra, add the columns, and pass an `MfaConfig`:

```bash
pip install "crudauth[mfa]"
```

```python
import os

from crudauth import CRUDAuth, MfaConfig, make_auth_identity

Identity = make_auth_identity(mfa=True)

class User(Base, Identity):
    __tablename__ = "users"

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY=os.environ["SECRET_KEY"],
    mfa=MfaConfig(
        issuer="Acme",
        encryption_key=os.environ["MFA_ENCRYPTION_KEY"],
        required=lambda user: user.is_superuser,
    ),
)
```

`make_auth_identity(mfa=True)` adds four columns: `totp_secret_encrypted`, `totp_confirmed_at`,
`totp_last_step` and `mfa_recovery_codes`. An existing table maps them with `column_map=` like any
other field, and `CRUDAuth` raises at startup if any is missing.

`encryption_key` encrypts the authenticator secrets at rest, so a database leak doesn't hand out
second factors. It's a Fernet key (a string or `bytes`), and it must differ from `SECRET_KEY`:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

To rotate it, pass a list with the new key first: `encryption_key=[new_key, old_key]`. New secrets
use the first key, and existing ones keep decrypting with the old one.

`required` decides who must use MFA: `False` (the default, so it's up to each user), `True`, or a
sync or async function of the user row. It's checked when a user logs in with a password (and with
OAuth when `oauth=True`, see [OAuth](#oauth)): sessions and refresh tokens that already exist when you
turn it on keep working until they end. With MFA unset, nothing about login changes.

## Enrolling

A signed-in user enrolls in two calls. Setup takes the password, so a stolen session can't attach
an authenticator the owner doesn't have. An account without a password (one that signs in only
through OAuth) has nothing to re-enter, so it must have signed in within the last 10 minutes on
the session making the request, or hold an active [sudo](sudo.md) elevation. Otherwise setup
answers `403` with "Sign in again to continue", and your frontend sends the user back through
the provider. `CRUDAuth(fresh_sign_in_seconds=...)` sets the window, and `0` closes the route to
such accounts, leaving enrollment to your own code (`auth.mfa.begin_setup` / `confirm_setup`).
A bearer token carries no sign-in time, so it's refused there:

```bash
curl -X POST http://localhost:8000/mfa/totp/setup -b jar.txt \
  -H "X-CSRF-Token: <token>" -H "Content-Type: application/json" -d '{"password": "..."}'
# {"secret": "JBSWY3DPEHPK3PXP...", "otpauth_uri": "otpauth://totp/Acme%3Aalice%40x.com?secret=..."}
```

Render `otpauth_uri` as a QR code in your frontend (show `secret` too, for typing it in), then
confirm with a code from the app:

```bash
curl -X POST http://localhost:8000/mfa/totp/confirm -b jar.txt \
  -H "X-CSRF-Token: <token>" -H "Content-Type: application/json" -d '{"code": "123456"}'
# {"recovery_codes": ["abcd-efgh-jkmn-pqrs", ...]}
```

The recovery codes are shown once. Ask the user to store them: each one replaces a code a single
time, for when the phone is lost. `GET /mfa` returns `{"enabled", "required",
"recovery_codes_remaining"}` for an account page.

## Logging in

For an account with MFA, `/login` and `/token` check the password as usual but don't issue a
credential. They return a challenge instead:

```json
{"mfa_required": true, "challenge": "...", "expires_in": 300}
```

Your frontend asks for the code and posts both to `/mfa/verify`:

```bash
curl -X POST http://localhost:8000/mfa/verify -c jar.txt \
  -H "Content-Type: application/json" -d '{"challenge": "...", "code": "123456"}'
```

That returns exactly what the original login would have: session cookies and `{"csrf_token"}` for
`/login`, tokens for `/token`. `on_after_login` fires then, not after the password. A recovery code
works in place of `code`.

A challenge lasts `challenge_ttl_seconds` (five minutes), is used once, and dies after
`max_code_attempts` wrong codes (five). Wrong codes also count against the
[login lockout](../infra/rate-limiting.md#login-lockout). A correct password neither resets the
lockout nor counts against it, and only a correct code clears it, so a stolen password can't be used
to keep guessing codes. Earlier failed passwords and wrong codes share the lockout's budget (five
attempts a minute by default), so a user who mistyped their password a few times gets fewer tries at
the code before the lockout steps in. For a session
login, `/mfa/verify` refuses a `Sec-Fetch-Site: cross-site` request, like `/login` does.

Each code is six ASCII digits (spaces are ignored), valid for its 30-second step and one step either
side for clock drift. A step is accepted once per account, so a code can't be replayed, even by two
requests racing each other. A password reset or change voids any challenge still waiting for its
code.

## Required enrollment

When `required` applies to an account that isn't enrolled, login returns a setup challenge carrying
the secret:

```json
{"mfa_required": true, "challenge": "...", "expires_in": 300,
 "setup": {"secret": "...", "otpauth_uri": "otpauth://..."}}
```

The first valid code from the new authenticator both enrolls the account and finishes the login;
that `/mfa/verify` response adds `recovery_codes`. If the user leaves before entering the code, the
next login offers the same secret, so a QR code they already scanned keeps working, until the
password is reset or changed, which discards it.

Enrolling during login trusts the password: whoever first completes that login with the right
password chooses the authenticator. Turn `required` on for accounts whose passwords you trust, or
have existing users enroll from a signed-in session (`/mfa/totp/setup`) before you require it. A
required account can't disable MFA (`403`).

## Recovery codes, disabling

Enabling MFA doesn't sign out the account's other sessions or invalidate its refresh tokens. To sign
out the other sessions, revoke them from the hook, keeping the one that just enrolled:

```python
async def sign_out_elsewhere(user, *, db, context):
    current = context.request.cookies.get("session_id") if context.request else None
    await auth.sessions.revoke_all(user["id"], exclude=current)

auth = CRUDAuth(..., hooks=AuthHooks(on_after_mfa_enabled=sign_out_elsewhere))
```

Refresh tokens end when the user's `token_version` is bumped, as a password change does. An account
without a password (OAuth-only) enrolls without one, since there's nothing to check.

`POST /mfa/recovery-codes/regenerate` replaces all recovery codes, and `POST /mfa/totp/disable` turns
MFA off. Both take `{"code"}`: a current authenticator code, or a recovery code when the device is
gone. An administrator can reset a user's MFA without a code by calling `auth.mfa.disable(db, user)`.

## Sudo

With [sudo mode](sudo.md), an enrolled user can elevate with a code instead of the password:

```python
until = await auth.sudo.elevate(user, code=body.code, db=db, request=request)
```

## OAuth

OAuth logins skip MFA by default: the identity provider owns the second factor there. That includes
accounts `required` covers, so an account with a linked provider can sign in through it without a
code; `CRUDAuth` logs a warning at startup when `required` is set with OAuth configured and
`oauth=False`. When an OAuth
login [claims an account](oauth.md#account-linking) whose email was never verified, it also removes
any MFA enrollment on it, since whoever registered that account set it up. With
`MfaConfig(oauth=True)`, the callback returns a challenge for an account with MFA instead of a
session. In JSON mode it's the challenge body; in redirect mode it's a redirect to
`{oauth_default_redirect}#mfa_challenge=<challenge>` (by default `redirect_base_url`). The fragment never reaches a server, but it stays in
the browser history, so read it and remove it right away
(`history.replaceState(null, "", location.pathname + location.search)`). For a setup challenge that
arrives this way, `POST /mfa/challenge` with `{"challenge"}` returns its `setup` details. The
`/mfa/verify` response includes `redirect_to`, the landing path the OAuth login asked for.
`on_oauth_login` runs when the callback resolves the account, before the challenge, and doesn't
run again when the challenge is answered (see
[Provider data on every sign-in](oauth.md#provider-data-on-every-sign-in)).

## Your own login route

A hand-written login keeps the second factor by asking the service for a challenge before issuing
anything:

```python
user = await auth.authenticate_password(
    db, form.username, form.password, request=request, record_success=False
)
challenge = await auth.mfa.challenge_login(
    db, user, request=request, transport="session",
    lockout_identifier=form.username, options={"remember_me": form.remember_me},
)
if challenge is not None:
    return challenge
# no MFA for this account: the lockout is already cleared, issue the credential
```

`/mfa/verify` then finishes it through the named transport with those `options`.

## Mounting the routes on their own

`auth.router` includes the `/mfa` routes. An app that mounts CRUDAuth's routers one at a time
(`auth.oauth_router`, `auth.session_router`, ...) mounts them with
`app.include_router(auth.mfa_router)`, which raises `RuntimeError` when MFA isn't configured.

## Hooks

`on_after_mfa_enabled` and `on_after_mfa_disabled` fire when an account turns MFA on or off, and
`on_after_recovery_code_used` when a recovery code is spent, a good moment to email the user. All
three receive `user, db, context`. See [Hooks](../infra/hooks.md).

---

[Next: Registration →](../accounts/registration.md){ .md-button .md-button--primary }
