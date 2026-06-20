# Onboard an existing users table

You're adding auth to an app that already has a `users` table, with your own column names:
`email_address`, `pw_hash`, `is_admin`, maybe an integer `account_id` primary key. CRUDAuth speaks
in *logical* field names (`email`, `hashed_password`, `is_superuser`, and so on), and `column_map`
bridges the two, so you adopt the library without renaming a single column.

<p align="center">
  <img src="../assets/diagrams/field-contract-light.png#only-light" alt="CRUDAuth needs the logical fields email, username, hashed_password, is_superuser; column_map translates each to the actual columns on your users table (email_address, username, pw_hash, is_admin), so you never rename your schema for the library" width="100%">
  <img src="../assets/diagrams/field-contract-dark.png#only-dark" alt="CRUDAuth needs the logical fields email, username, hashed_password, is_superuser; column_map translates each to the actual columns on your users table (email_address, username, pw_hash, is_admin), so you never rename your schema for the library" width="100%">
</p>

## 1. Map the names you already have

Say this is the table you already run:

```python title="models.py"
from sqlalchemy.orm import Mapped, mapped_column
from myapp.db import Base

class User(Base):
    __tablename__ = "users"
    account_id: Mapped[int] = mapped_column(primary_key=True)
    email_address: Mapped[str] = mapped_column(unique=True)
    username: Mapped[str] = mapped_column(unique=True)
    pw_hash: Mapped[str] = mapped_column()
    is_admin: Mapped[bool] = mapped_column(default=False)
    # ... your own columns, untouched
```

Pass `column_map` as logical-name to your-column-name, and list only the ones that differ:

```python title="main.py"
auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    column_map={
        "id": "account_id",
        "email": "email_address",
        "hashed_password": "pw_hash",
        "is_superuser": "is_admin",
    },
)
```

Now CRUDAuth reads `account_id` where it means the user id, writes `pw_hash` for the password hash,
and checks `is_admin` for the superuser gate, while your schema stays exactly as it is. A column
whose name already matches (`username` here) needs no entry.

## 2. Add the bookkeeping columns you don't have

Your model needs a column for every logical field CRUDAuth actually uses. The identity ones you
already have (mapped above); the bookkeeping ones may be new to your table:

- `token_version` (int, default `0`) — the revocation epoch. Without it, bearer tokens aren't
  epoch-revocable and a password reset can't evict the user's other sessions. Add it if you use
  bearer tokens or want reset-as-eviction.
- `email_verified` (bool, default `false`) — required for the verification flow and the
  `current_user(verified=True)` gate.
- `is_active` (bool, default `true`) — lets you deactivate an account; absent, everyone is treated
  as active.

These degrade gracefully when missing (CRUDAuth assumes active, unverified, epoch 0), so add only
the ones whose feature you actually want. A migration that adds them with the defaults above is the
whole job.

## 3. Registration still writes only what you allow

Mapping names loosens nothing. The registration allowlist is enforced on the logical fields *and*
their mapped columns, so `is_admin` is exactly as ungated as `is_superuser` would be: a request
can't set it through the renamed column either. Your own columns ride alongside, untouched.

## What this buys you

The point of the field contract is that CRUDAuth never imposes a schema on you. It depends on a small
set of logical fields and reads them through `column_map`, so an existing table keeps its names, its
primary-key type, and its conventions, and auth fits *around* it. You add the few bookkeeping columns
whose features you want, map the rest, and nothing about your current model has to move.

## Where to go next

- Set server-owned columns on new accounts: [Server-set fields at signup](server-set-fields.md).
- The contract in depth: [UserRepository](../api/repository.md) and [Modeling your user](../learn/3-modeling-your-user.md).
