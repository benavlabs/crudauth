# Hooks

App-specific side effects (a welcome email, a trial grant, an audit log) belong in your code,
not forked into the auth flow. `AuthHooks` registers callbacks that fire at lifecycle points,
uniformly across every path (a password signup and an OAuth signup both run
`on_after_register`).

```python
from crudauth import CRUDAuth, AuthHooks

async def welcome(user, *, db, context):
    await send_welcome_email(user["email"])

auth = CRUDAuth(..., hooks=AuthHooks(on_after_register=welcome))
```

A hook may be sync or async. `user` is passed as a plain `dict`, not your ORM instance, so
your hooks don't couple to the model.

## The hooks

| Hook | Fires after | Receives |
|---|---|---|
| `on_after_register` | an account is created | `user, db, context` |
| `on_after_login` | a successful login | `user, request, context` |
| `on_after_logout` | a logout | `user, request, context` |
| `on_after_recovery_verified` | recovery-factor verification confirm | `user, db, context` |
| `on_after_password_reset` | password reset confirm | `user, db, context` |
| `on_after_email_changed` | email change confirm | `user, db, context` |
| `on_after_sudo` | a sudo elevation | `user, request, context` |

All hooks also receive a `context` keyword.

## HookContext

`context` carries ambient request info, so a hook can log or branch without re-deriving it:

| Field | What it is |
|---|---|
| `ip_address` | Resolved client IP. |
| `user_agent` | Raw user-agent string. |
| `transport` | Which transport authenticated (`"session"`, `"bearer"`, ...). |
| `request` | The FastAPI `Request`, when available. |
| `extra` | A dict for flow-specific extras. |

## Example: an audit log

```python
async def audit_login(user, *, request, context):
    await write_audit("login", user_id=user["id"], ip=context.ip_address, ua=context.user_agent)

auth = CRUDAuth(..., hooks=AuthHooks(on_after_login=audit_login))
```

---

[Next: API reference →](../../api/index.md){ .md-button .md-button--primary }
