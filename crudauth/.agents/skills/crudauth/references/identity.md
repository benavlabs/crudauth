# Identity: account shapes, the model contract, and column_map

crudauth reads an account's *shape* from your model and validates it against `IdentityConfig` at
`CRUDAuth` construction. The model is the single source of truth; the config only declares intent a
schema can't carry (login order, recovery factor). A mismatch fails closed at startup.

## `make_auth_identity` and `AuthUserMixin`

```python
from crudauth import make_auth_identity
from crudauth.models import AuthUserMixin   # == make_auth_identity()  (the default shape)

make_auth_identity(
    identifiers=("email", "username"),   # which columns can be a login identifier
    recovery="email",                    # the recovery factor: "email", another field name, or None
    oauth=True,                          # emit oauth-linkage columns (google_id, github_id, ...)
)
```

It returns a declarative mixin you inherit:

```python
class User(Base, make_auth_identity(identifiers=["username"], recovery="phone", oauth=False)):
    __tablename__ = "users"
    phone: Mapped[str | None] = mapped_column(String(32), unique=True, default=None)
```

### Columns the factory emits

`AuthUserMixin` (the default) emits: `id`, `email`, `username`, `hashed_password`, `is_active`,
`is_superuser`, `email_verified`, `token_version`, the oauth columns (`oauth_provider`, `google_id`,
`github_id`, `oauth_created_at`, `oauth_updated_at`), and `created_at` / `updated_at`.

- An identifier that isn't `email` drops the `email` column when `recovery` isn't email either.
- `oauth=False` drops the oauth columns.
- A non-email recovery factor emits a `{factor}_verified` bookkeeping flag (e.g. `phone_verified`), but
  you declare the factor column itself (e.g. a unique `phone`). `email_verified` is always emitted.

## `IdentityConfig`

```python
from crudauth import IdentityConfig
IdentityConfig(login=["email", "username"], recovery="email")   # the default
```

- `login`: the fields `/login` accepts, in resolution order. Each must be a **single-column unique**
  column on the model (a composite unique constraint does not count). Login matches against these
  fields; there is no `@`-in-the-string heuristic.
- `recovery`: the factor that verification and password reset operate on (`"email"`, another field
  name, or `None`). Pass it to `CRUDAuth(identity=IdentityConfig(...))`.

Construction raises if a `login` field isn't a unique column, if `recovery` isn't unique, if OAuth is
enabled without `email` in `login`, or if `email=` config is set without an `email` column.

## The three shapes, end to end

```python
# 1. Email + username (default): just inherit AuthUserMixin; omit identity=.

# 2. Username-only (no email, no recovery)
class User(Base, make_auth_identity(identifiers=["username"], recovery=None, oauth=False)):
    __tablename__ = "users"
auth = CRUDAuth(..., identity=IdentityConfig(login=["username"], recovery=None),
                register_schema=UsernameOnlyRegister)   # default /register body requires email
# Consequence: no /password/reset-request (no recovery), and current_user(verified=True) raises.

# 3. Phone recovery
class User(Base, make_auth_identity(identifiers=["username"], recovery="phone", oauth=False)):
    __tablename__ = "users"
    phone: Mapped[str | None] = mapped_column(String(32), unique=True, default=None)
auth = CRUDAuth(..., identity=IdentityConfig(login=["username"], recovery="phone"),
                channels=[SmsChannel()], register_schema=Register, register_extra_fields={"phone"})
```

## `column_map` — adopt an existing table

crudauth speaks *logical* field names; `column_map` maps each to your actual column. List only the
ones that differ:

```python
auth = CRUDAuth(..., column_map={
    "id": "account_id",
    "email": "email_address",
    "hashed_password": "pw_hash",
    "is_superuser": "is_admin",
})
```

Logical fields (the `column_map`-able contract): `id`, `email`, `username`, `hashed_password`,
`is_active`, `is_superuser`, `email_verified`, `token_version`, `oauth_provider`, `google_id`,
`github_id`, `oauth_created_at`, `oauth_updated_at`. (`created_at` / `updated_at` are emitted by the
mixin but are not part of the contract, so they aren't remapped.)

Bookkeeping columns degrade gracefully if absent: `is_active` → treated active, `email_verified` →
`False`, `token_version` → `0` (revocation/eviction becomes a no-op). Add the ones whose feature you
want. The registration allowlist gates the **mapped** column too (`is_admin` is as ungated as
`is_superuser`).

## Gotchas

- Account shape lives on the model, not re-declared in `IdentityConfig`. The config declares intent
  (order, factor); the columns come from the model.
- A `login` field must be single-column unique. Composite-only uniqueness raises at construction.
- `recovery=None` means no recovery endpoints mount and `current_user(verified=True)` raises.
- The `{factor}_verified` flag is set only by token redemption; it's gated on every write path
  (register allowlist, `new_user_defaults`, `new_user_fields`).
