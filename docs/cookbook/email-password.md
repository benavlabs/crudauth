# Email and password accounts

This is the account most apps start with: someone signs up with an email and a password, logs in,
confirms their address, and can reset the password if they forget it. By the end of this recipe
you'll have all of that running, with the security-sensitive parts (hashing, CSRF, login lockout,
non-leaking responses) already handled for you.

It's the same starting point as [Getting started](../getting-started.md), taken all the way to
verification and reset.

## Before you start

You need two things from your app: a FastAPI instance and an async SQLAlchemy session dependency.
If you don't have the session dependency yet, it's the usual async setup:

```python title="db.py"
from collections.abc import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

engine = create_async_engine("postgresql+asyncpg://localhost/app")
Session = async_sessionmaker(engine, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with Session() as session:
        yield session
```

CRUDAuth never opens connections itself. It borrows this dependency for every route, so it slots
into whatever database wiring you already have.

## 1. The user model

CRUDAuth doesn't own your users table; it adds the columns it needs to a model you control.
Inherit `AuthUserMixin` and you get the default shape: login by email or username, a password,
email verification, the OAuth-linkage columns, and the timestamps and flags CRUDAuth reads. Your
own columns sit right beside them.

```python title="models.py"
from sqlalchemy.orm import Mapped, mapped_column
from crudauth.models import AuthUserMixin
from myapp.db import Base

class User(Base, AuthUserMixin):
    __tablename__ = "users"
    full_name: Mapped[str | None] = mapped_column(default=None)
```

`AuthUserMixin` is the default output of a factory (`make_auth_identity()`); if you later want a
different shape, that's the knob, but for email and password the default is exactly right. Create
the table however you normally do (your migrations, or `Base.metadata.create_all` in dev).

## 2. Wire up CRUDAuth

`CRUDAuth` is the one object you configure. It needs your session dependency, your model, and a
secret to sign tokens with. Mounting its router is what creates the endpoints:

```python title="main.py"
from fastapi import FastAPI
from crudauth import CRUDAuth
from myapp.db import get_session
from myapp.models import User

auth = CRUDAuth(session=get_session, user_model=User, SECRET_KEY="change-me")

app = FastAPI()
app.include_router(auth.router)   # /register, /login, /logout, /me
```

That alone gives you working cookie-session auth: register, login, logout, and `/me`, with CSRF
protection and login lockout already on. In real life the secret comes from your environment, not
a string literal.

## 3. Add email delivery

Verification and reset need a way to actually send mail. CRUDAuth builds the message and the
signed link; you implement an `EmailSender` that delivers it. Prefer enqueueing onto a task queue
over blocking the request on SMTP:

```python title="main.py"
from crudauth import EmailConfig, EmailSender

class MySender(EmailSender):
    async def send(self, *, to, subject, body, kind):
        # crudauth already built the subject and body (with the link). You deliver it.
        await tasks.enqueue(send_email, to=to, subject=subject, html=body)

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    email=EmailConfig(sender=MySender(), frontend_url="https://app.example.com"),
)
```

Passing `email=` is what mounts the verify, reset, and change-email routes. `frontend_url` is
where the links point: your frontend reads the token out of the URL and posts it back to the
matching confirm endpoint. The `kind` argument tells your sender which message it's delivering
(verification, reset, and so on) so you can pick a template.

## 4. Register, log in, and protect a route

With the router mounted, the account endpoints are live:

```bash
# create an account
curl -X POST http://localhost:8000/register -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","username":"alice","password":"a-strong-one"}'

# log in by email OR username; -c saves the session + CSRF cookies to a jar
curl -X POST http://localhost:8000/login -c jar.txt -d "username=alice@example.com&password=a-strong-one"

# the built-in "who am I"
curl http://localhost:8000/me -b jar.txt
```

The `username` form field accepts either the email or the username; CRUDAuth resolves whichever
matches. Protecting your own routes is one dependency:

```python
from fastapi import Depends
from crudauth import Principal

@app.get("/dashboard")
async def dashboard(user: Principal = Depends(auth.current_user())):
    return {"id": user.user_id}
```

`current_user()` authenticates the request and hands your handler a `Principal`: the user's id,
their flags, and the loaded row. If the request isn't logged in it never reaches your code; it
gets a 401.

## 5. Email verification

Verification is two steps, request then confirm. The request endpoint returns the same response
whether or not the address exists, so it can't be used to probe who has an account:

```bash
curl -X POST http://localhost:8000/email/verify-request \
  -H "Content-Type: application/json" -d '{"email":"alice@example.com"}'
```

CRUDAuth signs a single-use, time-limited token and hands it to your sender inside a link to
`frontend_url`. Your page reads the `token` query parameter and posts it back:

```bash
curl -X POST http://localhost:8000/email/verify-confirm \
  -H "Content-Type: application/json" -d '{"token":"eyJ..."}'
```

That marks the address verified. To require a confirmed address on a route, add the gate:

```python
@app.get("/billing")
async def billing(user: Principal = Depends(auth.current_user(verified=True))):
    ...
```

## 6. Password reset

Reset is the same request/confirm shape, and CRUDAuth treats it as attacker eviction: a
successful reset bumps the user's token version and terminates their other sessions, so a leaked
session or bearer token dies with the reset.

```bash
curl -X POST http://localhost:8000/password/reset-request \
  -H "Content-Type: application/json" -d '{"email":"alice@example.com"}'

# the user clicks the link; your reset page posts the token + the new password:
curl -X POST http://localhost:8000/password/reset-confirm \
  -H "Content-Type: application/json" \
  -d '{"token":"eyJ...","new_password":"a-new-strong-one"}'
```

## What you got for free

Look at everything you didn't have to write: passwords are bcrypt-hashed, the login error is
uniform and constant-time (so it can't reveal which accounts exist), repeated failures trip an
escalating lockout, session cookies carry a CSRF token that mutations must echo back, and the
verify and reset request endpoints don't leak existence. That's the whole point of the default
shape: the safe behavior is what you get by saying nothing.

## Where to go next

- Send verification and reset over SMS too, or instead: [delivery channels](../guides/accounts/email.md#delivery-channels).
- No email at all: [Username-only accounts](username-only.md).
- Add "Sign in with Google": the [OAuth guide](../guides/auth/oauth.md).
- Set app columns at signup (a default tier, a derived name): [registration](../guides/accounts/registration.md#setting-columns-the-server-controls).
- Going to production: [storage and lifespan](../guides/infra/storage.md) covers Redis and multiple workers.
