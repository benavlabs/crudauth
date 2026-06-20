# Why CRUDAuth?

CRUDAuth handles authentication for FastAPI: sessions, JWT, OAuth, and email flows, over
your own SQLAlchemy user model. This page covers what it does, what it doesn't, and when to
use something else.

## Auth is small to write and easy to get wrong

A login endpoint is a dozen lines. The security-relevant part is what those lines leave out:

```python
@app.post("/login")
async def login(form: OAuth2PasswordRequestForm = Depends(), db=Depends(get_session)):
    user = await get_user_by_username(db, form.username)
    if not user:
        raise HTTPException(401, "Bad credentials")     # returns faster than the real
                                                        # path, so it leaks which
                                                        # usernames exist

    if not bcrypt.checkpw(form.password.encode(), user.hashed_password.encode()):
        raise HTTPException(401, "Bad credentials")     # no lockout, and bcrypt cuts
                                                        # the password off at 72 bytes

    return {"token": jwt.encode({"sub": str(user.id)}, SECRET)}   # can't be revoked
```

This works; it's also a user-enumeration timing oracle, has no brute-force lockout,
truncates long passwords, and issues tokens you can't revoke. None of that shows up in a
demo; it shows up in a pentest.

CRUDAuth turns the hardened behavior on by default; mounting the router gives you login,
logout, register, and `/me` with escalating lockout, timing-equalized verification, a
SHA-256 pre-hash so bcrypt never truncates, synchronizer-token CSRF, trusted-proxy IP
handling, and token revocation:

```python
auth = CRUDAuth(
    session=get_session,
    user_model=User,
    SECRET_KEY="change-me"
)
app.include_router(auth.router)
```

You CAN write the hardened version yourself; the point is not having to rebuild and
re-audit it in every project.

## One identity, regardless of transport

A browser app wants a cookie session with CSRF. An API, mobile app, or CLI wants a
stateless bearer token. Many libraries tie one of those to the dependency your routes call,
so supporting both means a second identity path through every endpoint.

CRUDAuth resolves any transport to the same `Principal`. Your route asks for the principal;
it never depends on how the request authenticated.

<p align="center">
  <img src="assets/diagrams/identity-light.png#only-light" alt="A browser session cookie with CSRF and an API/CLI bearer JWT with scopes both funnel into CRUDAuth, which resolves the first credential present into one Principal (user_id, scopes, is_superuser, user row) that the route gates on regardless of transport" width="100%">
  <img src="assets/diagrams/identity-dark.png#only-dark" alt="A browser session cookie with CSRF and an API/CLI bearer JWT with scopes both funnel into CRUDAuth, which resolves the first credential present into one Principal (user_id, scopes, is_superuser, user row) that the route gates on regardless of transport" width="100%">
</p>

Adding bearer tokens to a session app is a change to your `CRUDAuth(...)` config, not to
your authorization code:

```python
@app.get("/me")
async def me(user: Principal = Depends(auth.current_user())):
    return {"id": user.user_id}      # same whether a cookie or a token authenticated
```

When more than one credential is present, the first transport you list wins. Gates like
`superuser`, `scopes`, and `verified` are expressed once, against the principal.

## Your user model stays yours

CRUDAuth adapts to your SQLAlchemy model instead of owning it. Inherit a mixin, or map the
logical fields onto a table you already have:

```python
# greenfield: inherit the columns crudauth needs, add your own freely
class User(Base, AuthUserMixin):
    full_name: Mapped[str | None] = mapped_column(default=None)

# existing table: map the contract instead of renaming your schema
auth = CRUDAuth(
    session=get_session, user_model=LegacyAccount, SECRET_KEY=...,
    column_map={
        "id": "account_id",
        "email": "email_address",
        "hashed_password": "pw_hash"
    },
)
```

Side effects (welcome email, trial grant, audit log) go in hooks, not a fork of the
library. A hook fires on every path that creates or authenticates a user, so password
signup and OAuth signup run the same code:

```python
async def welcome(user, *, db, context):
    await send_welcome_email(user["email"])

auth = CRUDAuth(..., hooks=AuthHooks(on_after_register=welcome))
```

## What CRUDAuth doesn't do

CRUDAuth is a focused library, not an identity platform.

!!! note "Reach for something else when"

    **You want a ready-made user-management UI.** CRUDAuth gives you the auth surface, not
    the screens. Pair it with [CRUDAdmin](https://github.com/benavlabs/crudadmin).

    **You'd rather not run auth at all.** A hosted provider (Auth0, Clerk, WorkOS) owns more
    of the problem, at a price and a vendor dependency.

    **You need enterprise SSO.** CRUDAuth does OAuth 2.0 social login, not SAML or SCIM
    provisioning.

    **You only need one "Sign in with Google".** A single OAuth flow with no sessions or
    registration is lighter with `Authlib` directly.

    **You're not on FastAPI and SQLAlchemy.** CRUDAuth is built on both.

## Adopt it incrementally

Each step is additive, and none of them change how your routes authorize:

1. **Start with sessions.** The default gives cookie auth, CSRF, lockout, and the auth routes.
2. **Add an API.** Put `BearerTransport()` in `transports=`.
3. **Add social login.** Pass `oauth={...}` with your provider credentials.
4. **Add email flows.** Implement the `EmailSender` port; CRUDAuth signs and verifies the tokens.
5. **Harden for production.** Move backends to Redis, set `trusted_proxy_hops`, gate sensitive actions behind `sudo`.
6. **Add policy.** Register `AuthHooks` for welcome emails, trials, and audit logging.

<div style="text-align: center; margin-top: 30px;">
    <a href="../#quick-start" class="md-button md-button--primary">
        Get started with CRUDAuth
    </a>
</div>
