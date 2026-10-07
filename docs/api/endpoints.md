# Endpoints

Every HTTP route CRUDAuth can mount, in one place. You get them by including the router:

```python
app.include_router(auth.router)
```

Which routes appear depends on your config (transports, `email=`, `oauth=`, `mfa=`, `management_routes`). For
the full behavior of each flow, follow the guide links; this page is the at-a-glance map.

**Auth column:** *none* = unauthenticated allowed; *any* = any authenticated transport; *session* =
a session principal (CSRF enforced on unsafe verbs); *authenticated* = any transport (CSRF automatic
on the session path, none on bearer).

## Always mounted

Present whenever `auth.router` is included, regardless of transports.

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/register` | none | Create an account. Strict field allowlist; `422` for a password that fails the [policy](../guides/accounts/passwords.md#password-policy) or a value longer than its column. ([Registration](../guides/accounts/registration.md)) |
| GET | `/me` | any | The authenticated user's id, scopes, and transport. |
| POST | `/set-password` | authenticated, signed in within `fresh_sign_in_seconds` | First password for an OAuth-only account; `400` if one already exists, `403` if the session signed in too long ago (sign in again), `422` if it fails the password policy. ([Passwords](../guides/accounts/passwords.md#setting-a-password-on-an-oauth-only-account)) |
| POST | `/change-password` | authenticated | Change a known password; `401` wrong current, `400` if unusable, `422` if the new one fails the password policy. Bumps `token_version`, revokes other sessions. ([Passwords](../guides/accounts/passwords.md#changing-a-known-password)) |

## Session transport

Mounted by `SessionTransport` (the default). ([Sessions](../guides/auth/sessions.md))

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/login` | none | Form `username`+`password`; sets cookies, returns `{"csrf_token"}`. |
| POST | `/logout` | session | Ends the current session, clears the session and bearer refresh cookies. |

### With `management_routes=True`

Opt-in device/CSRF management. ([Devices & sessions](../guides/accounts/session-management.md), [recipe](../cookbook/account-management.md))

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/sessions` | session | List active sessions ([`SessionInfo[]`](transports.md#sessioninfo)); `current` flags the caller. |
| DELETE | `/sessions/{id}` | session | Revoke one by the `id` from `GET /sessions` (ownership-checked; `404` if not found or not yours). |
| POST | `/logout-all` | session | Revoke all; `?keep_current=true` keeps the caller's. |
| POST | `/csrf/refresh` | session cookie | Re-mint the CSRF cookie (no CSRF header required; self-heals; `400` if CSRF disabled, `401` if no session). |

## Bearer transport

Mounted by `BearerTransport`. ([Bearer tokens](../guides/auth/bearer.md))

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/token` | none | Form login → `{"access_token", "token_type"}` (+ `refresh_token` when `refresh="body"`). |
| POST | `/refresh` | refresh token | Mint a new access token (cookie rides automatically, or `{"refresh_token"}` body). |
| POST | `/logout` | none | Only on a bearer-only app with `refresh="cookie"`: clears the refresh cookie. |

## Email & recovery

Mounted when `email=` and/or `channels=` is set with a recovery factor. The verify/reset request
bodies are shaped to the factor (`{"email": ...}` or `{"phone": ...}`). ([Email flows](../guides/accounts/email.md))

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/email/verify-request` | none | `{"<factor>", "redirect_to"?}` → send a verification link/code. Non-enumerable (uniform response). |
| POST | `/email/verify-confirm` | none | `{"token"}` → marks the recovery factor verified; echoes `redirect_to` when the link carried one. |
| POST | `/password/reset-request` | none | `{"<factor>", "redirect_to"?}` → send a reset link/code. Non-enumerable. |
| POST | `/password/reset-confirm` | none | `{"token", "new_password"}`; `422` if the password fails the policy, without using up the token. Evicts the user's other sessions, and echoes `redirect_to` when the link carried one. |
| POST | `/email/change-request` | authenticated | `{"new_email", "password", "redirect_to"?}`; `422` if `new_email` is longer than the `email` column. Mounted only when the model has an `email` column. |
| POST | `/email/change-confirm` | none | `{"token"}` → applies the new address; echoes `redirect_to` when the link carried one. |

## OAuth

Mounted per provider in `oauth={...}` (needs a `SessionTransport` + `redirect_base_url`). The paths below are the defaults; `oauth_paths` and `oauth_response_mode` change the paths and switch both routes to JSON responses. ([OAuth](../guides/auth/oauth.md#custom-paths-and-json-responses))

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/oauth/{provider}/authorize` | none | Start the flow; `?redirect_to=` (same-origin relative) for the post-login landing. |
| GET | `/oauth/{provider}/callback` | none | Finish the flow, link/create the user, establish a session. |

## Two-factor authentication

Mounted by `mfa=MfaConfig(...)`. With MFA, `/login` and `/token` return
`{"mfa_required": true, "challenge", "expires_in"}` (plus `setup` for a required account that
isn't enrolled) instead of a credential for accounts that use it. ([Two-factor authentication](../guides/auth/mfa.md))

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/mfa/verify` | none | `{"challenge", "code"}` → the credential the login started (cookies or tokens), plus `recovery_codes` after enrollment. `401` wrong code, `400` bad challenge. |
| POST | `/mfa/challenge` | none | `{"challenge"}` → `{"setup"}` details of a live setup challenge (for OAuth redirects). |
| GET | `/mfa` | authenticated | `{"enabled", "required", "recovery_codes_remaining"}`. |
| POST | `/mfa/totp/setup` | authenticated | `{"password"}` → `{"secret", "otpauth_uri"}`; `400` if already enabled. An account without a password sends `{}` and must have signed in within `fresh_sign_in_seconds` (`403` otherwise). |
| POST | `/mfa/totp/confirm` | authenticated | `{"code"}` → `{"recovery_codes"}`, shown once. |
| POST | `/mfa/totp/disable` | authenticated | `{"code"}` (authenticator or recovery); `403` when MFA is required. |
| POST | `/mfa/recovery-codes/regenerate` | authenticated | `{"code"}` → new `{"recovery_codes"}`. |

## Not a mounted route: sudo

Sudo elevation is a primitive plus a gate, not an endpoint. Build your own `POST /sudo` calling
`auth.sudo.elevate(...)`, and gate sensitive routes with `auth.require_sudo()`. ([Sudo mode](../guides/auth/sudo.md))

## Mounting a subset

You don't have to mount everything. `auth.session_router` and `auth.bearer_router` expose just that
transport's routes, and `auth.current_user()` works on your own routes whether or not you mount any of
CRUDAuth's.
