# Transports: session, bearer, and running both

A transport is an authentication channel. Each implements the same port and resolves to the same
`Principal`, so your routes don't change when you add or narrow transports. Pass instances in
`transports=[...]`; the default is `[SessionTransport()]`.

## SessionTransport (browsers)

```python
from crudauth import SessionTransport, CookieConfig
SessionTransport(cookies=CookieConfig(secure=True, samesite="lax"), backend="memory")
```

Adds `/login` (form-encoded `username` + `password`; `username` accepts any configured login field),
`/logout`, and the server-side session record. Mutating requests must echo the CSRF token from the
session cookie. Sessions and CSRF follow `CRUDAuth(redis_url=...)` / `CRUDAuth(redis_client=...)`;
`redis_url=`, `redis_client=` or `backend="memory"` on the transport overrides that for its own storage.

- Cookies are `secure=True` by default — serve over HTTPS. A session cookie may **never** be
  `SameSite=None` (rejected at construction).
- Sessions and CSRF tokens are stored under an HMAC of their value keyed with `SECRET_KEY`, never
  the raw id; rotating `SECRET_KEY` signs everyone out. Signing in again ends the session the
  browser presented.
- `session_timeout_minutes` is an idle timeout; `absolute_timeout_hours=N` also caps a session from
  sign-in.
- Two apps on CRUDAuth side by side (an admin panel beside the main app) each need their own
  `cookie_name`, `csrf_cookie_name`, `storage_prefix` and `csrf_storage_prefix`, or one's session
  resolves in the other on a shared Redis. Their lockout counters too: `CRUDAuth(rate_limit_prefix=...)`
  (or `prefix=` on `redis_rate_limiter` / `store.rate_limiter`), or failures in one lock the same
  username out of the other.
- A logout route of your own: `await session_transport.complete_logout(request, response, db)` ends
  the session, clears the cookies and runs `on_after_logout` (CSRF header required on a live session).
- `backend="database"` (or just `CRUDAuth(database_store=...)`) keeps sessions and CSRF tokens in
  the database.
- `storage=` / `csrf_storage=` take stores you built (any `AbstractSessionStorage`), instead of
  memory or Redis; not combinable with `backend`, `redis_url`, `redis_client` or `storage_prefix`.

## BearerTransport (API / mobile / CLI)

```python
from crudauth import BearerTransport
BearerTransport(
    access_ttl=900,             # access-token lifetime, seconds (default 900)
    refresh_ttl_days=30,
    refresh="cookie",           # "cookie" (httpOnly) or "body" (returned in JSON)
    default_scopes=["me:read"],
    grantable_scopes=["me:read", "reports:read", "reports:write"],
    refresh_cookie_path=None,   # e.g. "/refresh" to keep the cookie off every request
)
```

Adds `POST /token` (form-encoded login → `{"access_token": ..., "token_type": "bearer"}`, plus
`refresh_token` in the body when `refresh="body"`) and `POST /refresh`. Send the access token as
`Authorization: Bearer <token>`.

- `/refresh` with the cookie strategy rides the cookie automatically; with `refresh="body"` it reads a
  JSON `{"refresh_token": "..."}` (cookie is checked first, then that field).
- **Scopes are clamped to `grantable_scopes`** at login and re-clamped at `/refresh`, so a token can't
  self-grant beyond the ceiling, and tightening the ceiling drops a removed scope from tokens minted
  off existing refresh tokens.
- **Revocation:** JWTs are stateless; a `token_version` epoch on the user invalidates every token
  issued before a password reset in one step.

## Both at once

```python
auth = CRUDAuth(..., transports=[SessionTransport(), BearerTransport()])
```

- **First credential present wins**, in list order. List the one you want to win first.
- A transport returns nothing when its credential is **absent** (try the next); it **raises** for a
  credential present-but-invalid (a tampered token, a failed CSRF check), even under `optional=True`.
- Both yield the same `Principal`, so `current_user()` accepts either. Narrow a route with
  `current_user(transport="bearer")` / `"session"` / `["session", "bearer"]`.
- **CSRF is a session-transport property only** — enforced on cookie mutations, irrelevant to bearer.
  A request carrying both a session cookie and a bearer token authenticates by whichever transport is
  listed first; with the session first, its mutations need `X-CSRF-Token`.
- `/login` (and `/token` with `refresh="cookie"`) refuse `Sec-Fetch-Site: cross-site` with `403`.
- `/logout` clears every transport's cookies, including the bearer refresh cookie; a bearer-only app
  with `refresh="cookie"` gets its own `POST /logout` for that. After idle expiry, `/logout` just
  clears the cookies.
- A session stores the user's `token_version` at login; a password reset or change (which bumps it)
  ends every other session even one created from a password check that raced the reset.

## Custom transport

Implement the `Transport` port from `crudauth.core` (one `authenticate(request, ctx)` method that
returns `ctx.build_principal(...)` or `None`), optionally `contributes_routes()`, and pass an instance
in `transports=[...]`. Build the `Principal` via `ctx.build_principal(...)`, never construct it
directly. Resolve the user with `ctx.resolve_user(user_id)` (cached per request).
