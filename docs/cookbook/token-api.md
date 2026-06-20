# A token API (bearer tokens)

Browsers want cookies; everything else wants a token. For a mobile app, a CLI, an SPA, or a
service-to-service caller, CRUDAuth issues stateless JWT access tokens and pairs each with a
long-lived refresh token. The client logs in once, sends the access token in the `Authorization`
header, and refreshes when it expires. No cookies, no CSRF.

This recipe assumes a FastAPI app, an async SQLAlchemy session dependency, and a user model (the
default `AuthUserMixin` is fine; bearer auth works with any account shape).

## 1. Wire up the bearer transport

`BearerTransport` is the whole setup. For a CLI or mobile client that stores its own refresh token,
return it in the response body; for a browser SPA, leave it as the default httpOnly cookie:

```python title="main.py"
from crudauth import CRUDAuth, BearerTransport
from myapp.db import get_session
from myapp.models import User

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    transports=[BearerTransport(access_ttl=900, refresh="body")],
)
app.include_router(auth.router)
```

Adding the transport contributes two routes: `POST /token` to log in and `POST /refresh` to mint a
new access token.

## 2. Get a token

`POST /token` takes form-encoded credentials and returns the access token (and, with
`refresh="body"`, the refresh token):

```bash
curl -X POST https://api.example.com/token -d "username=alice&password=a-strong-one"
# {"access_token": "eyJ...", "refresh_token": "eyJ...", "token_type": "bearer"}
```

With the default `refresh="cookie"`, the refresh token is set as an httpOnly cookie instead, which
suits browser SPAs; `refresh="body"` suits clients that manage their own storage.

## 3. Use it

Send the access token in the `Authorization` header. Your routes gate exactly as they would under
any other transport:

```python
from fastapi import Depends
from crudauth import Principal

@app.get("/me")
async def me(user: Principal = Depends(auth.current_user())):
    return {"id": user.user_id}
```

```bash
curl https://api.example.com/me -H "Authorization: Bearer eyJ..."
```

## 4. Refresh

The access token is short-lived (15 minutes here). When it expires, call `POST /refresh` for a new
one:

```bash
curl -X POST https://api.example.com/refresh   # cookie strategy: the refresh token rides automatically
# {"access_token": "eyJ...", "token_type": "bearer"}
```

With `refresh="body"` there's no cookie, so your client sends the refresh token it stored, as JSON
(`/refresh` checks the cookie first, then a `refresh_token` field in the body):

```bash
curl -X POST https://api.example.com/refresh \
  -H "Content-Type: application/json" -d '{"refresh_token":"eyJ..."}'
# {"access_token": "eyJ...", "token_type": "bearer"}
```

## 5. Scopes

Bearer credentials carry scopes, and routes can require a subset. `grantable_scopes` is the ceiling
a token can ever hold; `default_scopes` is what a login gets when it asks for nothing:

```python
auth = CRUDAuth(
    ..., transports=[BearerTransport(
        default_scopes=["me:read"],
        grantable_scopes=["me:read", "reports:read", "reports:write"],
    )],
)

@app.get("/reports")
async def reports(user: Principal = Depends(auth.current_user(scopes=["reports:read"]))):
    ...
```

A client may narrow its scopes but never widen them past `grantable_scopes`, and that ceiling is
re-applied on every refresh, so tightening it drops a removed scope from tokens minted off existing
refresh tokens.

## What makes this safe to hand out

Statelessness is both the tradeoff and the design. An access token can't be revoked one by one, so
it's kept short (15 minutes), which caps the damage if one leaks. The refresh token is the only
long-lived secret, so it's the thing to protect: an httpOnly cookie in a browser, secure storage in
a CLI or mobile client. Revocation isn't lost, either: CRUDAuth embeds a `token_version` epoch in
every token and stores it on the user, so a password reset bumps that epoch and invalidates every
token issued before it in one step. And the `grantable_scopes` ceiling means a credential can never
widen its own authority, at login or at refresh.

## Where to go next

- Serve a browser app from the same backend: [Web and API in one backend](web-and-api.md).
- Let users sign in with Google and still call the API: [Sign in with Google](sign-in-with-google.md).
- Going to production (rotating secrets, Redis): [storage and lifespan](../guides/infra/storage.md).
