# Delivery channels

Recovery delivery is pluggable: CRUDAuth owns the token (mint, one-time-use, redemption); a
`DeliveryChannel` owns the medium and the copy. Email is the built-in channel
([EmailConfig](email.md)); pass `channels=` to [CRUDAuth](crud-auth.md) to add SMS, WhatsApp,
push, fired alongside it best-effort. See the
[email flows guide](../guides/accounts/email.md#delivery-channels) for usage.

::: crudauth.email.channel.DeliveryChannel

::: crudauth.email.channel.DeliveryIntent

::: crudauth.email.channel.EmailChannel
