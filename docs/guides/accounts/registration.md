# Registration

`POST /register` creates an account. The default body is `email`, `username`, and
`password`, and only `email` and `username` are persisted. Anything else is dropped unless
you opt it in. That allowlist is deliberate: adding a column to your model never silently
becomes settable at signup.

Registration is part of the base app, so it needs no extra configuration:

```python
auth = CRUDAuth(session=get_session, user_model=User, SECRET_KEY="change-me")
app.include_router(auth.router)   # /register, /login, /logout, /me
```

See [Getting started](../../getting-started.md) for the user model and `get_session`.

## Create an account

```bash
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "username": "alice", "password": "hunter2..."}'
```

`password` enforces `MIN_PASSWORD_LENGTH` (8). On success the `on_after_register` hook fires,
and if email verification is configured, a verification email is sent.

## Persisting extra fields

To let registration set one of your own columns, opt it in with `register_extra_fields`:

```python
auth = CRUDAuth(..., register_extra_fields={"full_name", "locale"})
```

To also accept those fields in the request body, supply a custom `register_schema`:

```python
from pydantic import BaseModel, EmailStr, Field

class RegisterIn(BaseModel):
    email: EmailStr
    username: str
    password: str = Field(min_length=8)
    full_name: str | None = None

auth = CRUDAuth(..., register_schema=RegisterIn, register_extra_fields={"full_name"})
```

A field declared in the schema but not opted into `register_extra_fields` is dropped (with a
startup warning). crudauth's privileged fields (`is_superuser`, `email_verified`, ...) can
**never** be opted in; declaring one is logged and ignored.

## Duplicate emails

Registering with an address that already exists returns the same generic response as a new
signup, so the endpoint isn't a user-enumeration oracle. If email is configured, the existing
account receives a security notice (throttled per address), not a welcome. A unique-constraint
race resolves to that same clean duplicate response rather than a 500.

---

[Next: Email flows →](email.md){ .md-button .md-button--primary }
