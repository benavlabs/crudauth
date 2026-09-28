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

`password` must meet the [password policy](passwords.md#password-policy), 8 characters by
default. A value longer than its `String(n)` column is
rejected before anything is written, whether it comes from the default body or a custom
`register_schema`, with a `422` in FastAPI's validation-error format: one `string_too_long` entry
per field, like the password rule's `string_too_short`. An email is measured the way it's
stored, trimmed and lowercased. On success the `on_after_register` hook fires, and if email
verification is configured, a verification email is sent.

## Persisting extra fields

To let registration set one of your own columns, opt it in with `register_extra_fields`:

```python
auth = CRUDAuth(..., register_extra_fields={"full_name", "locale"})
```

To also accept those fields in the request body, supply a custom `register_schema`:

```python
from pydantic import BaseModel, EmailStr

class RegisterIn(BaseModel):
    email: EmailStr
    username: str
    password: str
    full_name: str | None = None

auth = CRUDAuth(..., register_schema=RegisterIn, register_extra_fields={"full_name"})
```

The password policy runs on a custom schema too, so `password` doesn't need its own length rule.

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
is the OAuth display name, with the email local-part as a fallback. It isn't truncated, so slice
it to fit a length-limited column (`ctx.suggested_name[:50]`). Return a dict or a Pydantic model.

The difference from `register_extra_fields` is the trust boundary: this is fed a server-built
context, never the request body, so a client can't set these values. `new_user_defaults` merges
first, then `new_user_fields`, so a derived value can override a constant. Both are gated like
the allowlist: a CRUDAuth-owned field (`is_superuser`, `email_verified`, the password, the oauth
ids, the PK) is dropped and warned, never set.

## Registering users from your own route

An app that doesn't mount `/register` — because signup needs its own response shape, or its own
columns — writes the user row itself. CRUDAuth's allowlist protects its own route, not yours, so
the privileged fields become yours to refuse:

```python
class SignUp(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    username: str
    password: str
```

Nothing privileged is declared, `extra="forbid"` turns an attempt into a 422, and the row is built
from those fields plus a hash — never from `**payload.model_dump()`, which carries whatever the
schema grew since.

Assert it, so a field added later can't reopen it:

```python
def test_signup_accepts_no_privileged_field():
    assert not auth.repo.gated_register_fields(SignUp.model_fields)
```

[`gated_register_fields`](../../api/repository.md#crudauth.repository.UserRepository.gated_register_fields) answers with the
privileged fields a set of names contains, by logical name *and* by mapped column, so a `column_map`
alias is caught too. The full set is `crudauth.REGISTRATION_GATED_FIELDS`, and what registration
keeps by default is `crudauth.REGISTRATION_ALLOWED_FIELDS`.

**Why `email_verified` matters most.** A provider login links to an existing account with that
email, and CRUDAuth *claims* the account when it isn't verified: the password becomes unusable,
MFA is cleared, `token_version` is bumped and every session is terminated. That's what stops
someone registering under an address they don't own and keeping access after its owner signs in
with Google. A signup route that accepts `email_verified` lets them skip it — they register as
already verified, so the claim never runs and their password still works on the account the owner
now uses. The same goes for `google_id` and `github_id`: they decide which account a provider
login resolves to.

## Duplicate emails

Registering with an address that already exists returns the same generic response as a new
signup, so the endpoint isn't a user-enumeration oracle. The same holds for the recovery value
when it isn't a login field (an email that only recovers a username account, or a phone number)
and for any other unique column you let registration write. If delivery is configured, the owner
of a taken email or recovery value receives a security notice (throttled per address), not a
welcome. Both paths hash the password, so they take the same time too. A username is a public
handle, so a taken one is reported. A unique-constraint race resolves to that same clean
duplicate response rather than a 500.

The `register` rate limit counts only signups that pass validation (the body, the password
policy and the column lengths), so someone retrying a rejected password doesn't use up the
budget.

---

[Next: Email flows →](email.md){ .md-button .md-button--primary }
