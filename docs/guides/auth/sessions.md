# Sessions

Sessions are CRUDAuth's default transport. With no `transports=` argument you get cookie
auth backed by a server-side session store, CSRF protection, and the `/login`, `/logout`,
`/register`, and `/me` routes:

```python
from crudauth import CRUDAuth

auth = CRUDAuth(session=get_session, user_model=User, SECRET_KEY="change-me")
app.include_router(auth.router)
```

To configure it, pass a `SessionTransport` explicitly:

```python
from crudauth import CRUDAuth, SessionTransport, CookieConfig

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    redis_url="redis://localhost:6379/0",
    transports=[
        SessionTransport(
            session_timeout_minutes=30,
            max_sessions_per_user=5,
            cookies=CookieConfig(secure=True, samesite="lax"),
        ),
    ],
)
```

## The routes you get

| Method & path | What it does |
|---|---|
| `POST /register` | Create an account (`email`, `username`, `password`). |
| `POST /login` | Log in with a configured login field (`username` or `email` by default) + `password`; sets the cookies. |
| `POST /logout` | Terminate the current session and clear the cookies. |
| `GET /me` | Return the authenticated user's identity. |

`POST /login` is a form post and accepts a `remember_me` flag (see below). To gate your own
routes, see [Protecting routes](protecting-routes.md).

### A login of your own

Need a custom login (a different form, an extra step)? Call `auth.authenticate_password` for the
hardened credential check (the shared lockout, timing-equalized verification, and the
disabled-account check) and establish the session yourself, instead of reassembling those by hand:

```python
@app.post("/my-login")
async def my_login(body: LoginIn, request: Request, response: Response, db: DbDep):
    user = await auth.authenticate_password(db, body.username, body.password, request=request)
    sid, csrf = await auth.sessions.create_session(request, user_id=auth.repo.user_id(user))
    auth.sessions.set_session_cookies(response, sid, csrf)
    return {"csrf_token": csrf}
```

A wrong password raises `UnauthorizedException`, a tripped lockout `RateLimitException` - the same
responses `/login` gives. See [Use the building blocks](../../cookbook/use-the-building-blocks.md).

## How a session works

On a successful `POST /login`, CRUDAuth:

1. Verifies the credentials (with lockout and timing equalization).
2. Creates a session record in the backend (in-memory or Redis).
3. Generates a CSRF token bound to the session.
4. Sets an `httponly` `session_id` cookie and a readable `csrf_token` cookie.

On later requests the session transport reads `session_id`, validates it against the backend,
slides its idle timeout forward, and (on unsafe methods) checks CSRF before returning the
`Principal`.

The store never holds the session id or the CSRF token themselves: each is kept under an HMAC of
its value keyed with your `SECRET_KEY`. Whoever can read Redis can't sign in with what they read,
and changing `SECRET_KEY` signs everyone out.

Signing in again from a browser that still presents a session ends that session first. The
browser drops the old cookie anyway, so it stays usable only to whoever copied it. Other
browsers' sessions are untouched.

<p align="center">
  <img src="../../assets/diagrams/session-model-light.png#only-light" alt="The browser holds a httpOnly session_id cookie and a JS-readable csrf_token cookie; the session_id is looked up in the server-side session store (memory or redis) which holds user_id, csrf_token and expiry; writes must echo csrf_token in the X-CSRF-Token header" width="100%">
  <img src="../../assets/diagrams/session-model-dark.png#only-dark" alt="The browser holds a httpOnly session_id cookie and a JS-readable csrf_token cookie; the session_id is looked up in the server-side session store (memory or redis) which holds user_id, csrf_token and expiry; writes must echo csrf_token in the X-CSRF-Token header" width="100%">
</p>

## CSRF

CSRF is on by default and uses the synchronizer-token pattern. The `csrf_token` cookie is
**not** `httponly` so your frontend can read it and echo it back in the `X-CSRF-Token` header
on mutating requests (`POST`, `PUT`, `PATCH`, `DELETE`):

```javascript
function csrfToken() {
  return document.cookie.split("; ").find(c => c.startsWith("csrf_token="))?.split("=")[1];
}

await fetch("/account", {
  method: "POST",
  headers: { "X-CSRF-Token": csrfToken(), "Content-Type": "application/json" },
  body: JSON.stringify({ ... }),
});
```

A mutating request with a missing or wrong header is rejected with `403`. Safe methods
(`GET`, `HEAD`, `OPTIONS`) are exempt. You can disable CSRF with `SessionTransport(csrf=False)`,
but don't unless something else terminates CSRF in front of crudauth.

## Remember me

`POST /login` accepts a `remember_me` form field. When set, the session and its cookie get
the longer `remember_me_days` lifetime instead of the default idle window:

```python
SessionTransport(remember_me_days=30)
```

## Cookie policy

`CookieConfig` controls the cookie attributes:

```python
CookieConfig(secure=True, samesite="lax", path="/")
```

`secure=True` (the default) means the cookies are only sent over HTTPS. For local development
over plain HTTP, set `secure=False` so the browser will store them. `SessionTransport` rejects
`samesite="none"`: session cookies stay `lax` or `strict`, so the frontend and the API must be on
the same site (for example `app.example.com` and `api.example.com`). For a frontend on another
site, use a [bearer token](bearer.md).

`POST /login` refuses a request the browser marks `Sec-Fetch-Site: cross-site` with `403`, so
another site can't sign a visitor into an account it controls. `POST /logout` clears the session
cookies, and the bearer refresh cookie when a `BearerTransport` with `refresh="cookie"` is
configured. It also works after the session expired: there is nothing left to protect, so it
just clears the cookies.

A session remembers the user's `token_version` from login. A password reset or change bumps it,
which ends every other session, including one whose login checked the old password just before
the reset and was stored just after.

## Multi-device sessions

Each login is a separate server-side session, so you can build "manage devices" and "sign
out everywhere" on top of `auth.sessions`:

```python
@app.get("/account/sessions")
async def list_sessions(user: Principal = Depends(auth.current_user())):
    return await auth.sessions.list_for_user(user.user_id)

@app.post("/account/sessions/{session}/revoke")
async def revoke_session(session: str, user: Principal = Depends(auth.current_user())):
    await auth.sessions.revoke_by_handle(session, owner_id=user.user_id)

@app.post("/account/sign-out-everywhere")
async def sign_out_all(user: Principal = Depends(auth.current_user())):
    await auth.sessions.revoke_all(user.user_id)
```

`max_sessions_per_user` caps how many concurrent sessions a user can have; the oldest is
evicted past the cap.

## Session lifetime

`session_timeout_minutes` (default 30) is an idle timeout: every authenticated request slides it
forward, so a session in use never ends on its own. `absolute_timeout_hours` caps a session from
sign-in, however active it stays, for an app that wants a periodic re-login:

```python
SessionTransport(session_timeout_minutes=30, absolute_timeout_hours=12)
```

It's unset by default.

## Two apps side by side

Two apps that both run CRUDAuth, an admin panel mounted beside the main app for instance, must not
share a session namespace. On one Redis, the same storage prefix lets a session id from one app
resolve in the other; in one browser, the same cookie name lets the second login overwrite the
first. Give the embedded app its own names:

```python
SessionTransport(
    cookie_name="admin_session",
    csrf_cookie_name="admin_csrf",
    storage_prefix="admin:session:",
    csrf_storage_prefix="admin:csrf:",
)
```

## Your own session store

To keep sessions somewhere other than memory or Redis (a database table, Memcached), implement
[`AbstractSessionStorage`](../../api/storage.md) and pass a store of sessions and one of CSRF
tokens:

```python
SessionTransport(storage=DatabaseSessions(prefix="session:"), csrf_storage=DatabaseCSRF(prefix="csrf:"))
```

The stores carry their own prefix and expiration, so they can't be combined with `backend`,
`redis_url`, `redis_client` or `storage_prefix`, and `csrf_storage` is required while CSRF is on.
`auth.initialize()` and `auth.shutdown()` open and close them like the built-in ones.

## Backends and lifespan

The in-memory backend is per-process, which is fine for development but breaks under multiple
workers. Use Redis in production, and open and close the connections in your app's lifespan:

```python
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app):
    await auth.initialize()
    yield
    await auth.shutdown()

app = FastAPI(lifespan=lifespan)
```

The full set of knobs is on the
[`SessionManager`](../../api/transports.md) reference.

---

[Next: Bearer tokens →](bearer.md){ .md-button .md-button--primary }
