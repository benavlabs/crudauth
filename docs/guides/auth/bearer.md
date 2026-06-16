# Bearer tokens

Bearer tokens are the transport for non-browser clients: APIs, mobile apps, and CLIs. A
client logs in once, gets a short-lived access token, and sends it in the `Authorization`
header. crudauth issues stateless JWTs and pairs them with a long-lived refresh token.

```python
from crudauth import CRUDAuth, SessionTransport, BearerTransport

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    transports=[SessionTransport(), BearerTransport(access_ttl=900, refresh="cookie")],
)
```

Adding `BearerTransport` contributes two routes: `POST /token` to log in and `POST /refresh`
to mint a new access token.

## Access and refresh tokens

<p align="center">
  <img src="../../assets/diagrams/token-lifecycle-light.png#only-light" alt="One long-lived refresh token, stored in an httpOnly cookie and sent only to /refresh, mints many short-lived 15-minute access tokens that carry the scopes" width="100%">
  <img src="../../assets/diagrams/token-lifecycle-dark.png#only-dark" alt="One long-lived refresh token, stored in an httpOnly cookie and sent only to /refresh, mints many short-lived 15-minute access tokens that carry the scopes" width="100%">
</p>

The access token is short-lived (15 minutes by default) and carries the scopes. The refresh
token is long-lived and only used to mint new access tokens. Keeping access tokens short
limits the damage if one leaks, since it expires quickly and can be revoked.

## Getting a token

`POST /token` takes form-encoded credentials and returns the access token:

```bash
curl -X POST https://api.example.com/token \
  -d "username=alice&password=hunter2"
# {"access_token": "eyJ...", "token_type": "bearer"}
```

By default the refresh token is set as an `httpOnly` cookie (`refresh="cookie"`). Set
`refresh="body"` to return it in the JSON response instead, which suits CLIs and mobile
clients that store it themselves.

## Using a token

Send the access token in the `Authorization` header. Your route gates the same way as any
other transport:

```python
@app.get("/me")
async def me(user: Principal = Depends(auth.current_user())):
    return {"id": user.user_id}
```

```bash
curl https://api.example.com/me -H "Authorization: Bearer eyJ..."
```

## Refreshing

When the access token expires, call `POST /refresh` to get a new one. With the cookie
strategy the refresh token rides automatically; with the body strategy, send it yourself.

```bash
curl -X POST https://api.example.com/refresh   # refresh cookie sent automatically
# {"access_token": "eyJ...", "token_type": "bearer"}
```

## Scopes

Bearer credentials carry scopes, and routes can require a subset:

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

`grantable_scopes` is the ceiling: a token can never request or refresh into scopes beyond
it, so a credential can't widen its own authority.

## Revoking tokens

JWTs are stateless, so they can't be deleted one by one. crudauth embeds a `token_version`
epoch in every token and stores it on the user. A password reset bumps the user's
`token_version`, which invalidates every token issued before the reset in one step.

## Configuration

| Parameter | Default | What it does |
|---|---|---|
| `access_ttl` | `900` | Access token lifetime, in seconds. |
| `refresh_ttl_days` | `30` | Refresh token lifetime, in days. |
| `refresh` | `"cookie"` | Where the refresh token lives: `"cookie"` (httpOnly) or `"body"`. |
| `default_scopes` | `None` | Scopes granted when none are requested. |
| `grantable_scopes` | `None` | The ceiling of scopes a token may hold. |
| `refresh_cookie_path` | `None` | Restrict the refresh cookie to a path (e.g. `/refresh`). |

See the [bearer transport reference](../../api/transports.md) for the full surface.

---

[Next: Multiple transports →](multiple-transports.md){ .md-button .md-button--primary }
