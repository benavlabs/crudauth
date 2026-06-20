# Identity contract

An account's *shape* (which columns exist) is read from your model; `IdentityConfig` carries the
*intent* a schema can't express, the login resolution order and the recovery factor, validated
against the model when `CRUDAuth` is built so a config that contradicts the model fails at
startup rather than splitting into a second source of truth.

- `make_auth_identity(identifiers=, recovery=, oauth=)` builds the user-column mixin for a shape;
  `AuthUserMixin` is its default output (email + username login, email recovery).
- `IdentityConfig(login=, recovery=)` declares the intent; pass it as `CRUDAuth(identity=...)`.

See the [account-shape recipes](../cookbook/index.md) for end-to-end examples.

::: crudauth.identity.IdentityConfig

::: crudauth.models.mixin.make_auth_identity
