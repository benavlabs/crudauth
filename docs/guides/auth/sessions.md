# Sessions

Sessions are crudauth's default transport. With no `transports=` argument you get cookie
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
    transports=[
        SessionTransport(
            backend="redis",
            redis_url="redis://localhost:6379",
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
| `POST /login` | Log in with `username` (or email) + `password`; sets the cookies. |
| `POST /logout` | Terminate the current session and clear the cookies. |
| `GET /me` | Return the authenticated user's identity. |

`POST /login` is a form post and accepts a `remember_me` flag (see below). To gate your own
routes, see [Protecting routes](protecting-routes.md).

## How a session works

On a successful `POST /login`, crudauth:

1. Verifies the credentials (with lockout and timing equalization).
2. Creates a session record in the backend (in-memory or Redis).
3. Generates a CSRF token bound to the session.
4. Sets an `httponly` `session_id` cookie and a readable `csrf_token` cookie.

On later requests the session transport reads `session_id`, validates it against the backend,
slides its idle timeout forward, and (on unsafe methods) checks CSRF before returning the
`Principal`.

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
over plain HTTP, set `secure=False` so the browser will store them. Use `samesite="none"`
(with `secure=True`) only if your frontend is on a different site than your API.

## Multi-device sessions

Each login is a separate server-side session, so you can build "manage devices" and "sign
out everywhere" on top of `auth.sessions`:

```python
@app.get("/account/sessions")
async def list_sessions(user: Principal = Depends(auth.current_user())):
    return await auth.sessions.list_for_user(user.user_id)

@app.post("/account/sessions/{session_id}/revoke")
async def revoke_session(session_id: str, user: Principal = Depends(auth.current_user())):
    await auth.sessions.revoke(session_id, owner_id=user.user_id)  # owner check prevents cross-user revoke

@app.post("/account/sign-out-everywhere")
async def sign_out_all(user: Principal = Depends(auth.current_user())):
    await auth.sessions.revoke_all(user.user_id)
```

`max_sessions_per_user` caps how many concurrent sessions a user can have; the oldest is
evicted past the cap.

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
