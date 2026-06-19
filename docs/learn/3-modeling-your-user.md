# Modeling your user

In chapter 2 you inherited `AuthUserMixin` and moved on; this chapter is about that model: the fields CRUDAuth relies on, how your own columns coexist with them, and how to point CRUDAuth at a `users` table you already have and can't rename. By the end the user model is fully yours, and you know exactly which parts of it auth touches.

## What the mixin gives you

`AuthUserMixin` adds the columns CRUDAuth reads and writes, grouped by what they're for:

```python
# core identity
id, email, username, hashed_password

# status flags
is_active, is_superuser, email_verified

# credential epoch
token_version

# oauth linkage
oauth_provider, google_id, github_id, oauth_created_at, oauth_updated_at

# timestamps
created_at, updated_at
```

Most of these you'll never set by hand - `hashed_password` is written by registration and password resets, never by you. `token_version` is a counter a password reset bumps to invalidate old tokens. `is_active` is the disabled-account switch: a `False` here fails login with the same uniform error as a wrong password, so a disabled user can't be told apart from a missing one. The OAuth columns stay empty until chapter 6 wires up a provider.

The two you do care about day one are `is_superuser` and `email_verified`, because they're what the `current_user(superuser=True)` and `verified=True` gates from chapter 2 check.

## Adding your own columns

Your columns sit right beside the mixin's; you declare them as usual and CRUDAuth ignores them:

```python title="models.py"
from sqlalchemy.orm import Mapped, mapped_column
from crudauth.models import AuthUserMixin
from myapp.db import Base

class User(Base, AuthUserMixin):
    __tablename__ = "users"
    full_name: Mapped[str | None] = mapped_column(default=None)
    locale: Mapped[str] = mapped_column(default="en")
```

That's the greenfield case: let the mixin define the auth columns, add whatever your app needs, and you're done. But what if you can't start from the mixin?

## When you already have a users table

CRUDAuth doesn't depend on your column *names*, it depends on a set of **logical fields** (the names the mixin block listed above), and a small adapter translates those to whatever your table actually calls them. So if you already have a `users` table, you don't need to rename the columns to fit the library; you map the contract instead.

<p align="center">
  <img src="../assets/diagrams/field-contract-light.png#only-light" alt="CRUDAuth needs the logical fields email, username, hashed_password, is_superuser; column_map translates each to the actual columns on your users table (email_address, username, pw_hash, is_admin), so you never rename your schema for the library" width="100%">
  <img src="../assets/diagrams/field-contract-dark.png#only-dark" alt="CRUDAuth needs the logical fields email, username, hashed_password, is_superuser; column_map translates each to the actual columns on your users table (email_address, username, pw_hash, is_admin), so you never rename your schema for the library" width="100%">
</p>

You pass that translation as `column_map`, logical name to your column name. Only list the ones that differ:

```python title="main.py"
auth = CRUDAuth(
    session=get_session,
    user_model=User,
    SECRET_KEY="change-me",
    column_map={
        "id": "account_id",
        "hashed_password": "pw_hash",
        "is_superuser": "is_admin",
    },
)
```

Now CRUDAuth reads `account_id` where it means `user_id`, writes `pw_hash` where it means the password hash, and checks `is_admin` for the superuser gate, while your schema stays exactly as it was. Your model still needs a column for every logical field, but each can be named whatever you already call it.

Naming is one half of fitting CRUDAuth to your model though, the other is controlling what it's allowed to write, and the riskiest write is the one a stranger triggers: registration.

## Which fields registration may set

Chapter 1 showed the mass-assignment trap: a registration handler that copies the request body onto your model lets an attacker send `"is_superuser": true` and walk in as an admin. CRUDAuth closes this by making registration an **allowlist**, not a free-for-all.

By default `/register` persists exactly two fields, `email` and `username` (plus the password, which it hashes). Anything else in the body is dropped. If you want signup to set one of your own columns, you opt it in by name:

```python
auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    register_extra_fields={"full_name", "locale"},   # now settable at signup
)
```

The allowlist is the whole point: adding `locale` to your model doesn't quietly make it settable at signup, you have to say so here. And the privileged fields, `is_superuser` and `email_verified`, can *never* be opted in; listing them is logged and ignored, so there's no configuration that turns registration into a privilege grant.

To change the request body itself (different validation rules, extra required inputs), pass your own Pydantic model as `register_schema`. The allowlist still applies on top: a field in your schema is persisted only if it's `email`, `username`, or opted into `register_extra_fields`.

## Filling columns the server owns

The columns you added earlier were safe to leave out at signup: `full_name` is nullable, `locale` has a default. Add a *required* column with no default, say `name: Mapped[str]`, and signup breaks: CRUDAuth builds the new row from the fields it knows (email, username, password), and your `NOT NULL` `name` isn't one of them.

`register_extra_fields` doesn't solve this on its own. It lets the *client* send `name`; it doesn't let the *server* set one, and it does nothing for the OAuth path, which has no form at all. For server-owned values, constant or derived, there's a separate seam:

```python
# a constant for everyone
auth = CRUDAuth(..., new_user_defaults={"tier_id": FREE})

# or derive it
def new_user_fields(ctx):
    return {"name": ctx.suggested_name}

auth = CRUDAuth(..., new_user_fields=new_user_fields)
```

This runs wherever CRUDAuth creates a user, password and OAuth alike, and it's fed a trusted context (the email, the OAuth profile, the database), never the request body. That's chapter 1's mass-assignment lesson again: the client decides what the client may send, the server decides what the server sets, and the two never blur. A privileged field returned here is dropped, the same way it is at the registration allowlist.

## Where this leaves you

The model is yours: the mixin supplies the auth columns (or `column_map` points at the ones you have), your own columns ride alongside untouched, and registration can set only what you've explicitly allowed. Auth touches a known, small slice of the row, and nothing else.

Next: sessions, cookies, and CSRF. We've taken the default session transport on faith for two chapters. Chapter 4 opens it up: the server-side session record, the synchronizer-token check, and managing a user's devices.
