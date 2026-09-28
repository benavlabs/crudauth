# UserRepository

The adapter between CRUDAuth's logical field names and your user model's actual columns.
Configure the mapping with `column_map=` on [CRUDAuth](crud-auth.md).

`crudauth.REGISTRATION_ALLOWED_FIELDS` is what registration keeps without opting in (`email`,
`username`), and `crudauth.REGISTRATION_GATED_FIELDS` is what it never accepts. An app that
registers users through its own route rather than `/register` checks its schema against them with
`gated_register_fields` below; see
[Registering users from your own route](../guides/accounts/registration.md#registering-users-from-your-own-route).

::: crudauth.repository.UserRepository
