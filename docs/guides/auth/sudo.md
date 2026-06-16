# Sudo mode

A logged-in session proves who the user is, but not that they're still at the keyboard right
now. Sudo mode adds a short re-authentication step in front of sensitive actions (close
account, rotate keys, change billing), so a session left open can't be used to do real
damage.

```python
from crudauth import CRUDAuth, SessionTransport, SudoConfig

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    transports=[SessionTransport()],
    sudo=SudoConfig(window_seconds=300, max_attempts=3, lockout_seconds=900),
)
```

Elevation is stamped on the server-side session, so it dies with the session (logout or
revocation clears it). That's why sudo requires a `SessionTransport`; configuring it without
one raises at startup.

## Elevating

There's no built-in sudo route, because the prompt is part of your UI. Build a small endpoint
that re-verifies the password and elevates the current session:

```python
from pydantic import BaseModel

class SudoIn(BaseModel):
    password: str

@app.post("/sudo")
async def sudo(body: SudoIn, request: Request, user: Principal = Depends(auth.current_user())):
    until = await auth.sudo.elevate(user, body.password, request=request)
    return {"elevated_until": until.isoformat()}
```

`elevate()` re-checks the password and stamps the session with an absolute expiry
(`window_seconds` from now). A wrong password raises `401`; a non-session credential raises
`403`.

## Gating an action

Add `auth.require_sudo()` to any route that needs a recent re-auth. It passes only while the
session holds an unexpired elevation, and returns `403` otherwise:

```python
@app.post("/account/close")
async def close_account(
    user: Principal = Depends(auth.current_user()),
    _: Principal = Depends(auth.require_sudo()),
):
    ...   # reached only within the sudo window
```

## Lockout

Repeated wrong passwords trip a dedicated sudo lockout, keyed separately from the login
lockout so one can't mask the other. Once tripped, `elevate()` raises `SudoLockoutError`
(`429` with a `Retry-After` header) and any standing elevation is cleared.

## Auditing

An `on_after_sudo` hook fires on every successful elevation, which is a good place to write
an audit record:

```python
from crudauth import AuthHooks

async def on_sudo(user, *, request, context):
    await audit_log("sudo", user_id=user["id"])

auth = CRUDAuth(..., hooks=AuthHooks(on_after_sudo=on_sudo))
```

---

[Next: Registration →](../accounts/registration.md){ .md-button .md-button--primary }
