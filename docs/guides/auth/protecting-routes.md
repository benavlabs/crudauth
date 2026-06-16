# Protecting routes

`auth.current_user()` builds a FastAPI dependency that authenticates the request and returns
a [`Principal`](../../api/principal.md). Every authorization rule is a keyword on that one
factory, so you compose access control instead of writing it.

```python
from fastapi import Depends
from crudauth import Principal

@app.get("/dashboard")
async def dashboard(user: Principal = Depends(auth.current_user())):
    return {"id": user.user_id}
```

With no keywords it just requires a valid credential: an authenticated request gets the
`Principal`, an anonymous one gets `401 Unauthorized`.

## The Principal

Whatever transport authenticated the request, the dependency yields the same object:

<p align="center">
  <img src="../../assets/diagrams/identity-light.png#only-light" alt="Session cookies and bearer tokens both resolve through CRUDAuth into one Principal carrying user_id, scopes, is_superuser, and the user row" width="100%">
  <img src="../../assets/diagrams/identity-dark.png#only-dark" alt="Session cookies and bearer tokens both resolve through CRUDAuth into one Principal carrying user_id, scopes, is_superuser, and the user row" width="100%">
</p>

| Field | What it is |
|---|---|
| `user_id` | The user's primary key. |
| `is_superuser` | Whether the user holds the superuser flag. |
| `email_verified` | Whether the user's email is verified. |
| `scopes` | The capability scopes carried by this credential. |
| `transport` | Which transport authenticated the request (`"session"`, `"bearer"`, ...). |
| `user` | Your resolved user row (the ORM instance). |

```python
@app.get("/me")
async def me(user: Principal = Depends(auth.current_user())):
    return {"id": user.user_id, "via": user.transport, "email": user.user.email}
```

## Authorization keywords

Each keyword adds a check. They stack, and a failed check raises the matching status.

```python
auth.current_user()                          # required, 401 if anonymous
auth.current_user(optional=True)             # returns None instead of raising
auth.current_user(superuser=True)            # 403 unless is_superuser
auth.current_user(verified=True)             # 403 unless email_verified
auth.current_user(scopes=["reports:read"])   # 403 unless the credential's scopes cover these
auth.current_user(transport="bearer")        # only accept this transport (or a list)
```

`scopes` is a superset check: the credential must carry every scope you list. `transport`
narrows which credentials are accepted, which is useful when an endpoint should be
API-only or browser-only.

## Combining keywords

Keywords compose, so a route can require several things at once:

```python
@app.get("/reports")
async def reports(
    user: Principal = Depends(auth.current_user(superuser=True, verified=True, scopes=["reports:read"])),
):
    ...
```

## Custom checks

`check=` runs your own predicate on the resolved principal, after the built-in keywords. It
can be sync or async. Returning `False` denies with `403`; to deny with a different status or
message, raise your own exception from inside the check.

```python
def owns_team(user: Principal) -> bool:
    return user.user.team_id is not None

@app.get("/team")
async def team(user: Principal = Depends(auth.current_user(check=owns_team))):
    ...
```

Returning anything that isn't `False` (including `None`) allows the request, so a
raise-to-deny callback that simply returns nothing on success also works.

## Optional authentication

Pass `optional=True` to make a route public but personalized. The dependency returns `None`
for anonymous callers instead of raising:

```python
@app.get("/products")
async def products(user: Principal | None = Depends(auth.current_user(optional=True))):
    if user is not None:
        ...  # personalize for the logged-in user
    return ...
```

A *present but invalid* credential (for example a session cookie that fails its CSRF check on
a mutation) still raises, even under `optional=True`. A tampered credential is treated as an
attack signal, not as "anonymous".

## Protecting a whole router

Attach the dependency at the router level to gate every route under it:

```python
from fastapi import APIRouter

admin = APIRouter(prefix="/admin", dependencies=[Depends(auth.current_user(superuser=True))])

@admin.get("/stats")
async def stats():
    ...  # already gated; reached only by superusers
```

Router-level dependencies enforce access but don't inject a value into the handler. If a
route needs the `Principal`, add `current_user()` to that route as well.

## Composing with rate limits and sudo

`current_user()` is one dependency among several. Combine it with throttling or
re-authentication on the same route:

```python
@app.post(
    "/account/close",
    dependencies=[Depends(auth.rate_limit("account"))],
)
async def close_account(
    user: Principal = Depends(auth.current_user(superuser=False)),
    _: Principal = Depends(auth.require_sudo()),
):
    ...
```

See the [rate limiting](../../api/ratelimit.md) and [sudo](../../api/sudo.md) reference
pages for those pieces.

---

[Next: Sessions →](sessions.md){ .md-button .md-button--primary }
