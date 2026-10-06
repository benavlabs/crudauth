# Email, recovery, and custom bodies

crudauth owns the recovery token (mint, one-time-use, TTL'd redemption); you own delivery and copy.
There are two layers: the **`EmailSender`** port (the built-in email channel's transport) for plain or
branded email, and the **`DeliveryChannel`** port for any medium (SMS, push) or per-user copy.

## EmailConfig + EmailSender

```python
from crudauth import CRUDAuth, EmailConfig, EmailSender

class MySender(EmailSender):
    async def send(self, *, to, subject, body, kind, context):
        await tasks.enqueue(send_email, to=to, subject=subject, html=body)

auth = CRUDAuth(..., email=EmailConfig(
    sender=MySender(),
    frontend_url="https://app.example.com",   # links point here: {frontend_url}{path}?token=...
    # verify_path / reset_path / change_path and *_ttl_hours are configurable
))
```

`email=` mounts the recovery routes. crudauth composes `subject` + a plain-text `body` (the link
included) and calls `send`. **Prefer enqueueing over blocking on SMTP** — the request waits on it;
a raised send is logged and swallowed on every flow, so the message is lost unless the queue retries.

### EmailContext — render your own HTML (since 0.4)

`send`'s `context` is an `EmailContext` with crudauth-owned render data:

```python
@dataclass(frozen=True)
class EmailContext:
    kind: EmailKind        # verify_email | verify_recovery | reset_password | change_email | existing_account | email_changed
    link: str | None       # assembled URL, token embedded; None for the existing_account / email_changed notices
    recipient: str
    expires_in: int        # seconds; 0 when link is None
```

```python
async def send(self, *, to, subject, body, kind, context):
    html = render(f"emails/{kind}.html", link=context.link, expires_in=context.expires_in)
    await tasks.enqueue(send_email, to=to, subject=subject, html=html)
```

- `context.link` is the **same** assembled URL that's inside `body` (one source). Build a real
  `<a href>` from it; don't regex `body`.
- `context` carries **no user-controlled fields and no bare token** — putting `username`/`email` into
  HTML is an XSS surface crudauth refuses to be. The token reaches you only embedded in `link`.
- `body` stays the plain-text fallback: a sender that ignores `context` produces the pre-0.4 email.

## DeliveryChannel — other media, or per-user copy

```python
from crudauth import DeliveryChannel, DeliveryIntent

class SmsChannel(DeliveryChannel):
    async def deliver(self, intent: DeliveryIntent, db) -> None:
        if intent.token is None:
            return  # existing_account / email_changed notices have no action
        msg = f"Verify: https://app/recover?token={intent.token}" if intent.kind == "verify_recovery" \
              else f"Reset: https://app/recover?token={intent.token}"
        await sms_client.send(to=intent.recipient, body=msg)

auth = CRUDAuth(..., channels=[SmsChannel()])
```

`DeliveryIntent`: `kind`, `token` (the bare token, for building your own URL), `user`
(`repo.to_dict`, contract fields only — load app columns off `db`), `recipient`, `expires_in`.

- A channel may use `db` (a live session) to load extra columns and personalize. This is the
  home for `Hi Alice`, because the channel owns its escaping.
- crudauth fires every configured channel **best-effort** and swallows per-channel failures, so raise
  freely on a provider error: it never surfaces to the caller (no enumeration oracle) and never stops
  the next channel.
- For a non-email recovery factor, verification arrives as `kind="verify_recovery"` (not the
  email-named `verify_email`). `reset_password` / `existing_account` are factor-neutral in name.
- `recipient` is the recovery value (email or phone) for verify/reset/existing_account, the new address
  for `change_email`, the previous address for `email_changed`.
- `change_email` reaches only channels with `sends_email = True` (the built-in `EmailChannel` sets it);
  set it on a custom channel that emails `recipient`. Change-email routes mount only if one exists.

## Endpoints and flows

Mounted by `email=` (and/or `channels=` when there's a recovery factor):

| Endpoint | Body | Notes |
|---|---|---|
| `POST /email/verify-request` | `{"<factor>": ..., "redirect_to"?}` | factor-shaped (email app: `email`; phone app: `phone`) |
| `POST /email/verify-confirm` | `{"token": ...}` | marks the factor verified |
| `POST /password/reset-request` | `{"<factor>": ..., "redirect_to"?}` | |
| `POST /password/reset-confirm` | `{"token", "new_password"}` | evicts the user's other sessions |
| `POST /email/change-request` | `{"new_email", "password", "redirect_to"?}` | authenticated; mounts only when the model has an `email` column and a `sends_email` channel |
| `POST /email/change-confirm` | `{"token"}` | |

`redirect_to` is where the app wants the person sent after confirming (an invite they signed up to
accept). It rides inside the signed token, so the emailed URL is unchanged and the destination
survives the link being opened on another device. Same-origin relative paths only, validated at mint
and again at redemption; anything else is dropped without failing the flow. Each confirm response
includes `redirect_to` only when the token carried one — the same key the OAuth callback and
`/mfa/verify` return. Calling the service directly, the three confirm methods return
`EmailFlowResult(user, redirect_to)`.

## Security rules

- **Request endpoints are non-enumerable.** They return a uniform response whether or not the account
  exists (and skip already-verified). Don't change them to reveal existence. An inactive account is
  treated as absent: sent nothing, and its outstanding links are refused at confirm.
- **`current_user(verified=True)` gates on the recovery factor**, not `email_verified`.
- A successful **password reset bumps `token_version`**, revoking the user's outstanding bearer tokens
  and other sessions.
- The `{factor}_verified` flag is set only by redeeming the delivered token; it is unsettable at signup.
- **Tokens are bound to account state** (an HMAC claim): a reset link dies when the password or recovery
  value changes, a change-email link when the password, email or `token_version` changes, a verify link
  when the address changes. A confirmed email change notifies the old address (`email_changed`).
- `/register` returns the same `202` for a taken email/recovery value/other unique column as for a new
  signup (a taken username is reported), and the `register` limit counts only validated signups.
