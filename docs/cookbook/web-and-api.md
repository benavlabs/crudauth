# Web and API in one backend

Plenty of apps are both: a browser frontend and an API for mobile or third parties, served by one
FastAPI backend. The browser wants a cookie session; the API wants a bearer token. With CRUDAuth you
turn on both transports and your route code doesn't change, because every transport resolves to the
same `Principal`.

This recipe assumes you've seen the session setup in [email and password](email-password.md) and the
[token API](token-api.md); here we run them together.

## 1. Enable both transports

List both. The order is precedence: the first transport whose credential is *present* wins.

```python title="main.py"
from crudauth import CRUDAuth, SessionTransport, BearerTransport
from myapp.db import get_session
from myapp.models import User

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    transports=[
        SessionTransport(),   # browsers: cookies + CSRF
        BearerTransport(),    # API / mobile / CLI: JWT
    ],
)
app.include_router(auth.router)
```

You now have the session routes (`/login`, `/logout`, ...) and the token routes (`/token`,
`/refresh`) on one app. A browser logs in at `/login` and rides a cookie; a client logs in at
`/token` and sends a header.

## 2. One route, either credential

A plain `current_user()` accepts whichever credential the request carries and hands your handler the
same `Principal` either way. You write the route once:

```python
@app.get("/me")
async def me(user: Principal = Depends(auth.current_user())):
    return {"id": user.user_id}     # works for a cookie session OR a bearer token
```

The same endpoint answers both clients with the same user:

```bash
# browser: the session cookie saved at /login
curl https://app.example.com/me -b jar.txt
# {"id": 42}

# API client: a bearer token from /token
curl https://app.example.com/me -H "Authorization: Bearer eyJ..."
# {"id": 42}
```

## 3. Narrowing a route to one transport

Some endpoints should accept only one kind of credential. Pass `transport=` to restrict it:

```python
@app.post("/api/jobs")
async def create_job(user: Principal = Depends(auth.current_user(transport="bearer"))):
    ...   # rejects a cookie session even if one is present

@app.get("/account")
async def account(user: Principal = Depends(auth.current_user(transport="session"))):
    ...   # browser-only
```

A list, `transport=["session", "bearer"]`, accepts a subset.

## 4. CSRF stays where sessions are

CSRF is a property of the session transport: it's enforced on cookie-authenticated mutations and is
irrelevant to bearer requests, which don't ride a cookie. So your bearer API paths never touch CSRF,
your browser paths are protected automatically, and neither your route code nor your API clients have
to think about it.

## One Principal, one authorization model

This is the payoff worth seeing clearly. You authorize against the `Principal` (its `user_id`,
`is_superuser`, scopes, your `check`), and that is the same object no matter which transport
authenticated. Adding a transport, dropping one, or narrowing a route to one of them never changes
how the route authorizes, because authorization was never coupled to the credential in the first
place.

The one rule to keep in mind is first-present-wins with a hard stop: a transport returns nothing when
its credential is absent (so the next one is tried), but a credential that's *present but invalid* (a
session cookie that fails CSRF, a tampered token) raises and fails the request, even under
`optional=True`, because a tampered credential is an attack signal, not "anonymous".

## Where to go next

- Add a third way in that also resolves to the same `Principal`: [Sign in with Google](sign-in-with-google.md).
- Per-route scopes for the API surface: the [bearer guide](../guides/auth/bearer.md#scopes).
- Going to production: [storage and lifespan](../guides/infra/storage.md).
