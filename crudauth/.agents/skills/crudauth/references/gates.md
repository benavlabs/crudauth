# Gates: current_user and the Principal

`auth.current_user(...)` builds a FastAPI dependency that authenticates the request once (cached on
`request.state`, so stacking gates and a `KeyBy.USER` rate limit does one authentication) and then
authorizes it. The handler receives a `Principal`.

## `current_user(...)` options

```python
auth.current_user(
    verified=False,     # require the recovery factor proven controlled
    superuser=False,    # require is_superuser
    scopes=None,        # list[str]; require these bearer scopes
    check=None,         # Callable[[Principal], Any], sync or async; denies only when it returns False
    optional=False,     # return None instead of 401 when unauthenticated
    transport=None,     # "session" | "bearer" | list; restrict to credential kinds
)
```

All are combinable; all run on the same shared `Principal`, per call.

```python
@app.get("/me")
async def me(u: Principal = Depends(auth.current_user())): ...

@app.get("/billing")
async def billing(u: Principal = Depends(auth.current_user(verified=True))): ...

@app.delete("/admin/{id}")
async def rm(id: int, u: Principal = Depends(auth.current_user(superuser=True))): ...

@app.get("/reports")
async def reports(u: Principal = Depends(auth.current_user(scopes=["reports:read"]))): ...

@app.get("/org")
async def org(u: Principal = Depends(auth.current_user(check=lambda p: p.user.org_id == 1))): ...

@app.get("/maybe")
async def maybe(u: Principal | None = Depends(auth.current_user(optional=True))):
    return {"anon": u is None}
```

## The `Principal`

```python
from crudauth import Principal

@dataclass
class Principal:
    user_id: Any                 # the PK, coerced to the column's python type
    scopes: tuple[str, ...]
    transport: str               # "session" | "bearer" | provider name
    user: Any                    # the loaded ORM row (your model)
    is_superuser: bool
    email_verified: bool         # email-specific; see warning below
    recovery_verified: bool      # the contract's recovery factor is proven
    metadata: dict[str, Any]
```

- **Gate on `recovery_verified` / `current_user(verified=True)`, not `email_verified`.** `email_verified`
  is `False` on a non-email account, so a custom `check=lambda p: p.email_verified` always-denies a
  username-only or phone app. `email_verified` exists for the `/me` payload and for email apps where it
  equals `recovery_verified`.
- `user` is your ORM row; read columns off it, but prefer the logical contract when writing code that
  must survive a `column_map` rename (a hardcoded `user.email` breaks a remapped/email-less model).

## Semantics

- **`check=` denies only on `False`.** Returning `False` → 403; `None` or any other non-`False` value
  does not deny. To deny with a custom status/message, raise your own exception from inside `check`.
  (Since 0.2.0; earlier the return was ignored entirely.)
- **`verified=True` raises at construction when the contract has `recovery=None`** — nothing to prove
  control of, so it's a config error, surfaced early, not a silent always-deny.
- **`transport=` narrows to a credential kind.** A `transport="bearer"` route rejects a cookie session
  even if one is present; pass a list to accept a subset.
- **`optional=True` still hard-fails a present-but-invalid credential.** A tampered token or a CSRF
  failure raises even under `optional`, because that's an attack signal, not "anonymous".

## Patterns

- **Role/ownership:** put the rule in `check=`; keep it a pure predicate on the `Principal`.
- **App policy (welcome email, trial grant):** don't inline it in a route; register an `AuthHooks`
  callback (`on_after_register`, `on_after_login`, ...) so it fires uniformly across every path.
- **Per-user rate limit:** `auth.rate_limit(action, key=KeyBy.USER)` resolves the user via the same
  cached authentication, so it composes with `current_user` without a second lookup.
