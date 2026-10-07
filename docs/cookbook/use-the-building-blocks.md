# Use the building blocks

Sometimes you don't want CRUDAuth to own your endpoints. You want *its pieces* — the hardened
password check, token minting, the session manager, the user repository — behind your own routes,
your own login, your own background jobs. CRUDAuth is built for that: the facade is a composition
root that wires everything from your config, and then hands you the wired services. The routes are
optional.

This recipe is the à-la-carte tour. It assumes the [email + password](email-password.md) base.

## The model: build the facade, use its parts

```python
auth = CRUDAuth(session=get_session, user_model=User, SECRET_KEY=..., transports=[...])
# Mount as much or as little as you want:
app.include_router(auth.session_router)   # just /login, /logout
# app.include_router(auth.router)         # ...or everything
# ...or nothing, and write your own routes over the pieces below.
```

What you get off `auth`:

| Reach for | What it is |
|---|---|
| `auth.repo` | the [`UserRepository`](../api/repository.md): `get_by_email`, `resolve_login`, `create`, `update`, `token_version`, ... |
| `auth.sessions` | the [`SessionManager`](../api/transports.md#sessionmanager): `create_session`, `revoke`, `revoke_all`, CSRF, lockout |
| `auth.sudo` | the [`SudoManager`](../api/sudo.md): `elevate`, `is_elevated` |
| `auth.emails` | the [`EmailFlowService`](../api/email.md) (or `None`): `request_password_reset`, `reset_password`, ... The confirm methods return `EmailFlowResult(user, redirect_to)`. |
| `auth.oauth` | the [`OAuthAccountService`](../api/oauth.md) (or `None`): `get_or_create_user`; a hand-written callback then runs `auth.hooks.run_oauth_login(...)` ([OAuth](../guides/auth/oauth.md#provider-data-on-every-sign-in)) |
| `auth.signed_in_recently(principal)` | whether the session signed in within `fresh_sign_in_seconds` (or holds sudo), for gating your own routes on a fresh sign-in |
| `auth.current_user(...)` | the gate dependency — works on *your* routes |
| `auth.rate_limit(...)` / `auth.require_sudo()` | the other dependencies |

Plus the pure functions, exported from the package root: `get_password_hash`, `verify_password`,
`is_unusable_password`, `make_unusable_password`, and `get_password_hash_async` /
`verify_password_async`, which run the bcrypt work in a worker thread so an async route doesn't
block the event loop.

## Your own login, with the real hardening

The one rule: for the auth-critical flows, **don't reassemble the hardening from raw pieces** — call
the primitive that carries it. `auth.authenticate_password` is the exact credential check behind
`/login` and `/token`: the shared escalating lockout, timing-equalized verification (no
user-enumeration oracle), and the disabled-account check. Hand-rolling those yourself is how
enumeration and lockout-bypass bugs happen.

```python
@app.post("/my-login")
async def my_login(body: LoginIn, request: Request, response: Response, db: DbDep):
    user = await auth.authenticate_password(db, body.username, body.password, request=request)
    sid, csrf = await auth.sessions.create_session(request, user_id=auth.repo.user_id(user))
    auth.sessions.set_session_cookies(response, sid, csrf)
    return {"csrf_token": csrf}
```

A wrong password raises `UnauthorizedException` (401); a tripped lockout raises `RateLimitException`
(429) — the same responses the built-in route gives, because it's the same code.

## Your own token, with the clamp and the epoch

`auth.issue_tokens` is the issuance behind `/token`: scopes are clamped to the bearer transport's
`grantable_scopes` (a caller can't self-grant) and both tokens carry the `token_version` epoch (so a
password reset revokes them). Reach for this instead of the raw `create_access_token` — the raw
function skips the clamp and the epoch, which is exactly what makes a hand-minted token a liability.

```python
@app.post("/service-token")
async def service_token(
    admin: Annotated[Principal, Depends(auth.current_user(superuser=True))],
    db: DbDep,
):
    robot = await auth.repo.get_by_email(db, "robot@example.com")
    return auth.issue_tokens(robot, scopes=["read"])   # {"access_token", "token_type", "refresh_token"}
```

## A protected route of your own

`current_user()` is just a dependency; it doesn't care whether you mounted CRUDAuth's routes.

```python
@app.get("/whoami")
async def whoami(user: Annotated[Principal, Depends(auth.current_user())]):
    return {"id": user.user_id, "via": user.transport}
```

## Triggering recovery yourself

When `auth.emails` is configured it drives the verify/reset/change flows with the same token
mint/verify the endpoints use:

```python
if auth.emails is not None:
    await auth.emails.request_password_reset(db, email)   # sends over your channel(s)
```

## When to use which

- **Mount the built-in routes** for the standard flows — they're hardened and maintained.
- **Use the building blocks** for the bespoke parts: a custom login screen, a token minted in a
  webhook, a profile endpoint, an admin tool, a migration script. You get the wired services and the
  hardened primitives without CRUDAuth owning your URL space.

The line to remember: the hardening lives in `authenticate_password` and `issue_tokens`, not in the
routes. Use those two and the rest is just your code calling `auth.repo` / `auth.sessions`.

## Where to go next

- The full surface, symbol by symbol: [API reference](../api/index.md) ([`CRUDAuth`](../api/crud-auth.md), [`UserRepository`](../api/repository.md), [Transports](../api/transports.md)).
- Device & session management as built-in routes: [Account & device management](account-management.md).
