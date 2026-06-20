# Registration

`POST /register` creates an account. The default body is `email`, `username`, and
`password`, and only `email` and `username` are persisted. Anything else is dropped unless
you opt it in. That allowlist is deliberate: adding a column to your model never silently
becomes settable at signup.

The fields here are the default (email + username) account shape. The shape is configurable, so
a username-only or other-recovery app registers different fields; see the
[account-shape recipes](../../cookbook/index.md) and the
[identity contract](../../api/identity.md).

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
startup warning). CRUDAuth's privileged fields (`is_superuser`, `email_verified`, ...) can
**never** be opted in; declaring one is logged and ignored.

## Setting columns the server controls

`register_extra_fields` is for fields the *client* sends. For columns the *server* fills,
especially ones that are `NOT NULL` with no default, or values you derive, use
`new_user_defaults` (constants) or `new_user_fields` (a callback). Both run wherever CRUDAuth
creates a user: `/register` **and** OAuth signup.

```python
# constant values
auth = CRUDAuth(..., new_user_defaults={"tier_id": FREE_TIER_ID})

# derived values (sync or async; the callback may read the database)
def new_user_fields(ctx):
    return {"name": ctx.suggested_name, "tier_id": FREE_TIER_ID}

auth = CRUDAuth(..., new_user_fields=new_user_fields)
```

The callback gets a [`NewUserContext`](../../api/provisioning.md): `email`, `username`,
`source` (`"register"` or `"oauth"`), the live `db`, the validated `register_data`, and the
`oauth` profile, so you can branch on the path or derive from the provider. `ctx.suggested_name`
is the OAuth display name, with the email local-part as a fallback. Return a dict or a Pydantic
model.

The difference from `register_extra_fields` is the trust boundary: this is fed a server-built
context, never the request body, so a client can't set these values. `new_user_defaults` merges
first, then `new_user_fields`, so a derived value can override a constant. Both are gated like
the allowlist: a CRUDAuth-owned field (`is_superuser`, `email_verified`, the password, the oauth
ids, the PK) is dropped and warned, never set.

## Duplicate emails

Registering with an address that already exists returns the same generic response as a new
signup, so the endpoint isn't a user-enumeration oracle. If email is configured, the existing
account receives a security notice (throttled per address), not a welcome. A unique-constraint
race resolves to that same clean duplicate response rather than a 500.

---

[Next: Email flows →](email.md){ .md-button .md-button--primary }
