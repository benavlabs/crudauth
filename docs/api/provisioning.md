# Provisioning

App-supplied columns for new-user creation. `new_user_fields` on [CRUDAuth](crud-auth.md)
receives this context and returns your own columns to set at signup, on both the password and
OAuth paths; `new_user_defaults` is the constant-only shortcut. See the
[registration guide](../guides/accounts/registration.md#setting-columns-the-server-controls)
for usage.

::: crudauth.provisioning.NewUserContext
