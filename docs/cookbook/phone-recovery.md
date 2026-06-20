# Phone recovery (SMS verify and reset)

Some apps are phone-first: users sign up with a handle and a phone number, and recover their
account by SMS rather than email. CRUDAuth's recovery is factor-agnostic, so you point the
contract at a phone column, implement one delivery channel for SMS, and verification and password
reset run over the phone end to end, with no email anywhere.

This is the third account shape, alongside [email and password](email-password.md) and
[username-only](username-only.md). It assumes a FastAPI app, an async SQLAlchemy session
dependency, and an SMS provider (Twilio, Vonage, your own gateway, whatever you use).

## 1. The model

Ask the factory for a username login and a phone recovery factor, and declare the phone column
yourself. It's your column, so you own its type and constraints, and a recovery factor must be
unique:

```python title="models.py"
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column
from crudauth import make_auth_identity
from myapp.db import Base

class User(Base, make_auth_identity(identifiers=["username"], recovery="phone", oauth=False)):
    __tablename__ = "users"
    phone: Mapped[str | None] = mapped_column(String(32), unique=True, default=None)
```

Because the recovery factor is `phone`, the factory emits a `phone_verified` bookkeeping column
next to your `phone` (the same way email recovery has `email_verified`). You never set that flag;
CRUDAuth flips it when a verification token is redeemed.

## 2. An SMS delivery channel

CRUDAuth owns the token and its lifetime; a `DeliveryChannel` owns the medium and the copy.
Implement one `deliver` method, branch on the message kind, and send. For a phone-recovery app,
`intent.recipient` is already the user's phone number:

```python title="sms.py"
from crudauth import DeliveryChannel, DeliveryIntent

class SmsChannel(DeliveryChannel):
    async def deliver(self, intent: DeliveryIntent, db) -> None:
        if intent.token is None:
            return  # notices with no action (e.g. existing-account); nothing to send

        link = f"https://app.example.com/recover?token={intent.token}"
        if intent.kind == "verify_recovery":
            body = f"Verify your number: {link}"
        elif intent.kind == "reset_password":
            body = f"Reset your password: {link}"
        else:
            return  # email-specific kinds (change-email) don't apply to a phone app

        await sms_client.send(to=intent.recipient, body=body)
```

CRUDAuth fires every configured channel best-effort and swallows failures per channel, so you can
raise freely on a provider error: it never surfaces to the caller and never leaks whether an
account exists. Reliability (retry, queue) belongs inside the channel. Note the `kind` is
factor-neutral here: a phone verification arrives as `verify_recovery`, not the email-named
`verify_email`.

## 3. Wire it up

Declare the same shape to `CRUDAuth`, register the channel, and let `/register` accept the phone:

```python title="main.py"
from pydantic import BaseModel, Field
from crudauth import CRUDAuth, IdentityConfig
from myapp.db import get_session
from myapp.models import User
from myapp.sms import SmsChannel

class Register(BaseModel):
    username: str
    phone: str
    password: str = Field(min_length=8)

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    identity=IdentityConfig(login=["username"], recovery="phone"),
    channels=[SmsChannel()],
    register_schema=Register,
    register_extra_fields={"phone"},   # let signup persist your phone column
)
app.include_router(auth.router)
```

`register_extra_fields={"phone"}` opts your phone column into what `/register` is allowed to write;
everything else a request sends is still dropped. A channel plus a non-None recovery factor is what
mounts the recovery endpoints.

## 4. Register and log in

```bash
curl -X POST http://localhost:8000/register -H "Content-Type: application/json" \
  -d '{"username":"neo","phone":"+15551234567","password":"a-strong-one"}'
curl -X POST http://localhost:8000/login -c jar.txt -d "username=neo&password=a-strong-one"
```

## 5. Verify the phone

The verify endpoint takes the recovery factor in its body, so for this app it's `{"phone": ...}`,
not an email:

```bash
curl -X POST http://localhost:8000/email/verify-request \
  -H "Content-Type: application/json" -d '{"phone":"+15551234567"}'
# the user taps the SMS link; your page posts the token:
curl -X POST http://localhost:8000/email/verify-confirm \
  -H "Content-Type: application/json" -d '{"token":"eyJ..."}'
```

That sets `phone_verified`. Gate routes that need a proven number with `current_user(verified=True)`,
which now means "the recovery factor is verified," the phone here.

The path is still under `/email/` for historical reasons; the body and behavior are phone-shaped.
Read `email` in that URL as the recovery namespace, not the medium.

## 6. Reset the password

The same request-then-confirm shape, over the phone:

```bash
curl -X POST http://localhost:8000/password/reset-request \
  -H "Content-Type: application/json" -d '{"phone":"+15551234567"}'
curl -X POST http://localhost:8000/password/reset-confirm \
  -H "Content-Type: application/json" \
  -d '{"token":"eyJ...","new_password":"a-new-strong-one"}'
```

A successful reset evicts the user's other sessions, the same attacker-eviction behavior as the
email shape.

## What changed, and what didn't

Compare this to the [email and password](email-password.md) recipe and notice how little differs.
Registration, login, the session and CSRF, the escalating lockout, the signed single-use tokens,
the non-enumerable request endpoints, the session eviction on reset: all identical. Two things
changed, and only two. The recovery factor is a `phone` column instead of `email`, and recovery
messages leave through your `SmsChannel` instead of email. That is the whole point of a
factor-agnostic recovery contract: "verified" and "reset" are concepts, not email features, so a
new medium is a channel and a column, never a fork of the flow.

## Where to go next

- Want email and SMS both? Add an `EmailConfig` alongside `channels=[...]`; every channel fires, so
  the token goes out over each. See [delivery channels](../guides/accounts/email.md#delivery-channels).
- The other shapes: [email and password](email-password.md), [username-only](username-only.md).
- The full contract reference: [identity](../api/identity.md).
