# Endpoints

Every HTTP route CRUDAuth can mount, in one place. You get them by including the router:

```python
app.include_router(auth.router)
```

Which routes appear depends on your config (transports, `email=`, `oauth=`, `management_routes`). For
the full behavior of each flow, follow the guide links; this page is the at-a-glance map.

**Auth column:** *none* = unauthenticated allowed; *any* = any authenticated transport; *session* =
a session principal (CSRF enforced on unsafe verbs); *authenticated* = any transport (CSRF automatic
on the session path, none on bearer).

## Always mounted

Present whenever `auth.router` is included, regardless of transports.

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/register` | none | Create an account. Strict field allowlist. ([Registration](../guides/accounts/registration.md)) |
| GET | `/me` | any | The authenticated user's id, scopes, and transport. |
| POST | `/set-password` | authenticated | First password for an OAuth-only account; `400` if one already exists. ([Passwords](../guides/accounts/passwords.md#setting-a-password-on-an-oauth-only-account)) |
| POST | `/change-password` | authenticated | Change a known password; `401` wrong current, `400` if unusable. Bumps `token_version`, revokes other sessions. ([Passwords](../guides/accounts/passwords.md#changing-a-known-password)) |

## Session transport

Mounted by `SessionTransport` (the default). ([Sessions](../guides/auth/sessions.md))

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/login` | none | Form `username`+`password`; sets cookies, returns `{"csrf_token"}`. |
| POST | `/logout` | session | Ends the current session, clears cookies. |

### With `management_routes=True`

Opt-in device/CSRF management. ([Devices & sessions](../guides/accounts/session-management.md), [recipe](../cookbook/account-management.md))

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/sessions` | session | List active sessions ([`SessionInfo[]`](transports.md#sessioninfo)); `current` flags the caller. |
| DELETE | `/sessions/{session_id}` | session | Revoke one (ownership-checked; `404` if not found or not yours). |
| POST | `/logout-all` | session | Revoke all; `?keep_current=true` keeps the caller's. |
| POST | `/csrf/refresh` | session cookie | Re-mint the CSRF cookie (no CSRF header required; self-heals; `400` if CSRF disabled, `401` if no session). |

## Bearer transport

Mounted by `BearerTransport`. ([Bearer tokens](../guides/auth/bearer.md))

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/token` | none | Form login → `{"access_token", "token_type"}` (+ `refresh_token` when `refresh="body"`). |
| POST | `/refresh` | refresh token | Mint a new access token (cookie rides automatically, or `{"refresh_token"}` body). |

## Email & recovery

Mounted when `email=` and/or `channels=` is set with a recovery factor. The verify/reset request
bodies are shaped to the factor (`{"email": ...}` or `{"phone": ...}`). ([Email flows](../guides/accounts/email.md))

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/email/verify-request` | none | Send a verification link/code. Non-enumerable (uniform response). |
| POST | `/email/verify-confirm` | none | `{"token"}` → marks the recovery factor verified. |
| POST | `/password/reset-request` | none | Send a reset link/code. Non-enumerable. |
| POST | `/password/reset-confirm` | none | `{"token", "new_password"}`; evicts the user's other sessions. |
| POST | `/email/change-request` | authenticated | `{"new_email", "password"}`. Mounted only when the model has an `email` column. |
| POST | `/email/change-confirm` | none | `{"token"}` → applies the new address. |

## OAuth

Mounted per provider in `oauth={...}` (needs a `SessionTransport` + `redirect_base_url`). ([OAuth](../guides/auth/oauth.md))

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/oauth/{provider}/authorize` | none | Start the flow; `?redirect_to=` (same-origin relative) for the post-login landing. |
| GET | `/oauth/{provider}/callback` | none | Finish the flow, link/create the user, establish a session. |

## Not a mounted route: sudo

Sudo elevation is a primitive plus a gate, not an endpoint. Build your own `POST /sudo` calling
`auth.sudo.elevate(...)`, and gate sensitive routes with `auth.require_sudo()`. ([Sudo mode](../guides/auth/sudo.md))

## Mounting a subset

You don't have to mount everything. `auth.session_router` and `auth.bearer_router` expose just that
transport's routes, and `auth.current_user()` works on your own routes whether or not you mount any of
CRUDAuth's.
