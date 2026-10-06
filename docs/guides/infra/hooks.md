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

Hooks run after the operation is done (the account created, the session stored, the password
changed), so they can't block or undo it. An exception a hook raises is logged with its
traceback on the `crudauth.hooks` logger and the request still succeeds. A hook that writes
through `db` owns that work: commit it, or roll back on its own failure. For work that must not
be lost, enqueue it from the hook rather than doing it inline.

## The hooks

| Hook | Fires after | Receives |
|---|---|---|
| `on_after_register` | an account is created | `user, db, context` |
| `on_login_failed` | a refused password login | `identifier, user, reason, context` |
| `on_lockout` | a password login refused by the lockout | `identifier, retry_after, context` |
| `on_after_login` | a successful login | `user, request, context` |
| `on_after_logout` | a logout | `user, request, context` |
| `on_after_recovery_verified` | recovery-factor verification confirm | `user, db, context` |
| `on_after_password_reset` | password reset confirm | `user, db, context` |
| `on_after_password_changed` | in-session password change (`/change-password`) | `user, db, context` |
| `on_after_email_changed` | email change confirm | `user, db, context` |
| `on_after_sudo` | a sudo elevation | `user, request, context` |
| `on_after_mfa_enabled` | an account turns MFA on | `user, db, context` |
| `on_after_mfa_disabled` | an account turns MFA off | `user, db, context` |
| `on_after_recovery_code_used` | an MFA recovery code is spent | `user, db, context` |

All hooks also receive a `context` keyword.

`on_login_failed` gets the identifier as typed (untrusted input: escape it before it reaches a
page), `user` (the account it named, or `None` when it named none) and `reason`
(`"invalid_credentials"` or `"inactive"`). The response to the caller doesn't say which; the hook
can, for an audit log or an alert. `on_lockout` gets the identifier and how many seconds the
lockout has left. Both run on every password login (`/login`, `/token`, and
`auth.authenticate_password`), before the refusal is raised.

## HookContext

`context` carries ambient request info, so a hook can log or branch without re-deriving it:

| Field | What it is |
|---|---|
| `ip_address` | Resolved client IP. |
| `user_agent` | Raw user-agent string. |
| `transport` | Which transport authenticated (`"session"`, `"bearer"`, ...). |
| `request` | The FastAPI `Request`, when available. |
| `extra` | A dict for flow-specific extras. |
| `session_handle` | On a session login, the session's public handle, the same `id` `GET /sessions` lists. An audit log can name the session and match it to a later revocation without storing a credential. |

## Example: an audit log

```python
async def audit_login(user, *, request, context):
    await write_audit("login", user_id=user["id"], ip=context.ip_address, ua=context.user_agent)

auth = CRUDAuth(..., hooks=AuthHooks(on_after_login=audit_login))
```

---

[Next: API reference →](../../api/index.md){ .md-button .md-button--primary }
