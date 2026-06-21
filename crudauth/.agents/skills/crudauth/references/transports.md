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
session cookie. `backend="redis"` (with `redis_url=`) moves sessions, CSRF, and the one-time-token /
OAuth-state stores to Redis.

- Cookies are `secure=True` by default — serve over HTTPS. A session cookie may **never** be
  `SameSite=None` (rejected at construction).

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
  Your API paths never deal with CSRF; your browser paths are protected automatically.

## Custom transport

Implement the `Transport` port from `crudauth.core` (one `authenticate(request, ctx)` method that
returns `ctx.build_principal(...)` or `None`), optionally `contributes_routes()`, and pass an instance
in `transports=[...]`. Build the `Principal` via `ctx.build_principal(...)`, never construct it
directly. Resolve the user with `ctx.resolve_user(user_id)` (cached per request).
