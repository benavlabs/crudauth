# Username-only accounts (no email)

Not every app wants an email address. A throwaway-account service, an internal tool, a game with
handles: all of these just want a username and a password, with nothing to verify and nowhere to
send a reset. CRUDAuth supports this directly. Because it reads an account's *shape* from your
model, you declare a username-only shape and the whole stack (register, login, the gates) follows
along: no email column gets created, and no recovery endpoints get mounted.

This recipe assumes you already have a FastAPI app and an async SQLAlchemy session dependency (the
[email and password recipe](email-password.md) shows a minimal one if you need it).

## The idea: the model is the source of truth

CRUDAuth's columns come from a factory, `make_auth_identity`. The default it produces
(`AuthUserMixin`) is email + username login with email recovery, but you can ask for a different
shape, and the runtime reads back whatever the model actually has. So you don't configure "no
email" in two places and hope they agree; you declare it once, on the model, and CRUDAuth follows.

## 1. The user model

Call the factory with the shape you want. `identifiers=["username"]` makes username the login
field, `recovery=None` means there's no recovery factor, and `oauth=False` drops the OAuth columns
(OAuth needs an email, so it isn't available on this shape):

```python title="models.py"
from sqlalchemy.orm import Mapped, mapped_column
from crudauth import make_auth_identity
from myapp.db import Base

class User(Base, make_auth_identity(identifiers=["username"], recovery=None, oauth=False)):
    __tablename__ = "users"
    display_name: Mapped[str | None] = mapped_column(default=None)
```

This model genuinely has no `email` column. The auth columns are the username, the password hash,
the status flags, the token version, and timestamps, and your own columns (like `display_name`)
sit alongside them.

## 2. Wire up CRUDAuth

There are two things to tell `CRUDAuth`. First, the same shape, through `IdentityConfig`, so login
and the routes match the model. Second, a registration body without email, because the default
`/register` body requires one:

```python title="main.py"
from fastapi import FastAPI
from pydantic import BaseModel, Field
from crudauth import CRUDAuth, IdentityConfig
from myapp.db import get_session
from myapp.models import User

class Register(BaseModel):
    username: str
    password: str = Field(min_length=8)

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    identity=IdentityConfig(login=["username"], recovery=None),
    register_schema=Register,
)

app = FastAPI()
app.include_router(auth.router)   # /register, /login, /logout, /me
```

When `CRUDAuth` is built it checks the contract against your model and fails loudly if they
disagree: every field in `login` has to be a unique column (username is), and because
`recovery=None`, the verify and reset routes are never mounted. The config and the model can't
drift, because the model is the source of truth and the check runs at startup.

## 3. Register and log in

```bash
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" -d '{"username":"neo","password":"a-strong-one"}'

curl -X POST http://localhost:8000/login -c jar.txt -d "username=neo&password=a-strong-one"
curl http://localhost:8000/me -b jar.txt
```

Login resolves the identifier against the contract's `login` fields, which here is just username,
so `neo` matches by username and there's no email path to fall through to. Everything else, cookie
sessions, CSRF, the escalating login lockout, works exactly as it does for the email shape.

## What this shape gives up, on purpose

Choosing `recovery=None` is a real decision with three consequences worth being explicit about:

- **No password recovery.** There is no `/password/reset-request`, because the recovery router
  isn't mounted. A user who forgets their password can't reset it. That's the deliberate trade for
  holding no contact information; if it isn't the trade you want, you want a recovery factor (see
  below).
- **No `verified` gate.** `current_user(verified=True)` raises at construction on a `recovery=None`
  app. There's nothing to prove control of, so it's treated as a configuration error rather than a
  gate that silently always denies.
- **Usernames are probeable.** A duplicate registration returns `422 "Username already taken"`.
  Username is a public namespace (it's how every signup form's availability check works), so that's
  expected, and it's the deliberate opposite of the email path, which is non-enumerable.

## Growing into recovery later

If the app later wants password reset, you don't rebuild anything. Give users a contact factor and
flip the shape: add a unique `email` column, set `recovery="email"` in `IdentityConfig`, and the
recovery endpoints appear. The [email and password recipe](email-password.md) shows that shape end
to end, and the [identity contract](../api/identity.md) is the full reference for `login`,
`recovery`, and `make_auth_identity`.
