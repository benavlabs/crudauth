# Email flows

CRUDAuth runs three email flows: verify an address, reset a password, and change an address.
Each is a two-step request/confirm cycle. CRUDAuth composes the message and signs a
single-use token; you deliver the email; your frontend turns the click into a confirm call.

## Configure a sender

On top of the [base setup](../../getting-started.md), email needs two things: an
`EmailSender` (how a message goes out) and an `EmailConfig` (where the links point). Together
they enable the six routes below.

```python title="main.py"
from crudauth import CRUDAuth, EmailConfig, EmailSender

class MySender(EmailSender):
    async def send(self, *, to, subject, body, kind, context):
        # plain: deliver crudauth's text as-is. branded HTML: build your own
        # from context.link (the assembled URL), no need to parse it out of body.
        await tasks.enqueue(send_email, to=to, subject=subject, html=body)

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    email=EmailConfig(sender=MySender(), frontend_url="https://app.example.com"),
)
app.include_router(auth.router)   # adds the verify / reset / change routes
```

Prefer enqueueing onto a task queue over blocking on SMTP here: registration sends are
best-effort (a failure is logged), but the verify/reset/change flows surface a raised send as
a 5xx.

### Sending your own HTML

`body` is crudauth's plain-text default. To send a branded template, read `context`
([`EmailContext`](../../api/email.md)): `context.link` is the assembled, ready-to-click URL, so
you build a real button without regexing the link out of `body`, and `context.kind` /
`context.expires_in` round out the copy.

```python
async def send(self, *, to, subject, body, kind, context):
    html = render(f"emails/{kind}.html", link=context.link, expires_in=context.expires_in)
    await tasks.enqueue(send_email, to=to, subject=subject, html=html)
```

`context` carries crudauth-owned data only (link, kind, recipient, expiry), never the bare token
and never user-controlled fields, so the sender can't be an injection vector. For per-user copy
(`Hi Alice`), write a [delivery channel](#delivery-channels) instead: it gets the `db` handle and
the user row, and owns its own escaping.

<p align="center">
  <img src="../../assets/diagrams/email-flow-light.png#only-light" alt="Three-step email flow: a request endpoint always returns 200, CRUDAuth signs a single-use token and your EmailSender delivers the link, and the confirm endpoint verifies and consumes the token once" width="100%">
  <img src="../../assets/diagrams/email-flow-dark.png#only-dark" alt="Three-step email flow: a request endpoint always returns 200, CRUDAuth signs a single-use token and your EmailSender delivers the link, and the confirm endpoint verifies and consumes the token once" width="100%">
</p>

## The link, and your frontend's job

CRUDAuth puts the token in the link as a query parameter:

```text
{frontend_url}{path}?token=<signed-token>
# e.g. https://app.example.com/reset-password?token=eyJ...
```

That link points at **your** frontend, not at crudauth. Your page reads `token` from the URL
and POSTs it to the matching confirm endpoint. The paths default to `/verify-email`,
`/reset-password`, and `/confirm-email-change`, and are configurable on `EmailConfig`.

## Walk-through: password reset

```bash
# 1. the user asks for a reset (always returns 200, even if the address is unknown)
curl -X POST http://localhost:8000/password/reset-request \
  -H "Content-Type: application/json" -d '{"email": "alice@example.com"}'

# 2. they click the emailed link; your /reset-password page reads ?token=... and submits:
curl -X POST http://localhost:8000/password/reset-confirm \
  -H "Content-Type: application/json" \
  -d '{"token": "eyJ...", "new_password": "a-new-strong-one"}'
```

Verify and change-email follow the same shape, with different bodies (below).

## The routes

| Method & path | Body | What it does |
|---|---|---|
| `POST /email/verify-request` | `{email}` | Send a verification link. |
| `POST /email/verify-confirm` | `{token}` | Consume the token, mark `email_verified`. |
| `POST /password/reset-request` | `{email}` | Send a reset link. |
| `POST /password/reset-confirm` | `{token, new_password}` | Set the new password, revoke outstanding tokens. |
| `POST /email/change-request` | `{new_email, password}` | Authenticated; send a link to the **new** address. |
| `POST /email/change-confirm` | `{token}` | Swap the email and mark it verified. |

The `-request` endpoints always return `200`, whether or not the address exists, so they
don't leak which accounts are registered. Tokens are single-use and time-limited
(`verify_ttl_hours`, `reset_ttl_hours`, `change_ttl_hours` on `EmailConfig`).

## Delivery channels

Email is the built-in delivery channel, but the token isn't email-specific. CRUDAuth owns the
token (mint, one-time-use, redemption); a `DeliveryChannel` owns the medium and the copy. Pass
`channels=` to route the same reset/verify token over SMS, WhatsApp, push, or several at once:

If you only want a branded HTML *email* (not a new medium), you don't need a channel: read
`context.link` in your `EmailSender` ([Sending your own HTML](#sending-your-own-html) above). Reach
for a channel when you need a different medium, or per-user copy that loads data off the `db`.

```python
from crudauth import CRUDAuth, DeliveryChannel, DeliveryIntent, EmailConfig

class SMSChannel(DeliveryChannel):
    async def deliver(self, intent: DeliveryIntent, db) -> None:
        if intent.kind != "reset_password" or intent.token is None or db is None:
            return
        user = await db.get(User, intent.user["id"])   # load an app column synchronously
        if user and user.phone:
            link = f"https://app.example.com/reset-password?token={intent.token}"
            await sms.enqueue(to=user.phone, body=f"Reset your password: {link}")  # hand off

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    email=EmailConfig(sender=MySender(), frontend_url="https://app.example.com"),
    channels=[SMSChannel()],
)
```

Every configured channel fires for each flow, **best-effort and independent**: a channel that
raises is logged and skipped, and never stops another channel or changes the endpoint's
uniform `200` (so a dead integration can't leak which accounts exist or block the channel that
actually recovers the account). Reliability (retry, queueing) lives inside a channel.

`email=EmailConfig(...)` is just the built-in `EmailChannel`. With `channels=` and no
`EmailConfig`, the recovery endpoints still mount, and token lifetimes fall back to the
defaults (or pass `verify_ttl_hours` / `reset_ttl_hours` / `change_ttl_hours` to `CRUDAuth`).

`deliver(intent, db)` receives the message descriptor plus the request session. Two things to
know:

- `intent.recipient` is the **email address** (the recovery lookup is still keyed on email;
  per-field recovery like phone-as-identifier is a separate step). A non-email channel ignores
  it and loads its own destination, as the SMS example does.
- `intent.user` holds only CRUDAuth's logical fields, so an app column like `phone` isn't in
  it. Read it off `db` with `intent.user["id"]` (the session is present for verify/reset/change,
  `None` for the existing-account notice). Use `db` **synchronously** and never commit or
  capture it: it closes when the request ends, so read what you need, then enqueue the send
  (as above) rather than blocking on it.

## Hooks

`on_after_recovery_verified`, `on_after_password_reset`, and `on_after_email_changed` fire after
the matching confirm, so you can grant access, send a notice, or write an audit record.

## Security notes

- A password reset bumps the user's `token_version`, invalidating every bearer token issued
  before the reset, and evicts the user's other sessions.
- The change-email link is sent to the **new** address, so confirming it proves control.
- `-request` endpoints are throttled per address and per IP.

---

[Next: Passwords →](passwords.md){ .md-button .md-button--primary }
