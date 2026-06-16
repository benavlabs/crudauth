# Your first protected route

The last two chapters were almost all concept, this one on the other hand is almost all code. We'll stand up the smallest real thing CRUDAuth gives you: a route that only a logged-in user can reach. By the end you'll have registration, login, and one gated endpoint, and hopefully you'll understand every line that made it work.

You need a FastAPI app and an async SQLAlchemy session dependency already in place. Given those, this is about fifteen lines.

## The user model

CRUDAuth doesn't own your user table; it reads and writes a few fields on the model you already have. `AuthUserMixin` adds those fields (the id, email, username, password hash, and the flags behind chapter 0's Principal) so you don't spell them out by hand.

```python title="models.py"
from sqlalchemy.orm import Mapped, mapped_column
from crudauth.models import AuthUserMixin
from myapp.db import Base

class User(Base, AuthUserMixin):
    __tablename__ = "users"
    full_name: Mapped[str | None] = mapped_column(default=None)
```

Your own columns sit right next to the ones the mixin adds; `full_name` is here only to show that. Chapter 3 goes deep on this model, including how to fit it onto a table you don't control. For now the mixin is all you need.

The model is passive: it describes the row; something has to read a request and turn it into a logged-in user. That's the object you build next.

## Wire it up

`CRUDAuth` is the **composition root**: the one object you configure, that holds your transports and knows how to turn a request into an identity. It needs three things to start: the database session dependency it should use, your user model, and a secret to sign with.

```python title="main.py"
from fastapi import FastAPI
from crudauth import CRUDAuth
from myapp.db import get_session   # your dependency that yields an AsyncSession
from myapp.models import User

auth = CRUDAuth(session=get_session, user_model=User, SECRET_KEY="change-me")

app = FastAPI()
app.include_router(auth.router)   # mounts /register, /login, /logout, /me
```

`CRUDAuth(...)` builds the object, and `include_router` mounts the endpoints it generated. You passed no `transports=` argument, so you get the default: cookie sessions, with CSRF protection and login lockout already on. That's the chapter 1 list of defaults, switched on by saying nothing. In a real app the secret comes from the environment though, not a string literal, which we'll cover later.

## Register and log in

Mounting the router gave you four routes for free. Create an account and sign in:

```bash
# create an account
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "username": "alice", "password": "a-strong-one"}'

# log in; -c saves the session and CSRF cookies to a jar
curl -X POST http://localhost:8000/login -c jar.txt -d "username=alice&password=a-strong-one"

# the built-in "who am I" route
curl http://localhost:8000/me -b jar.txt
```

`/login` set two cookies: the session id and the CSRF token from chapter 0. From here, any request that sends the jar back (`-b jar.txt`) is authenticated. Try a wrong password and you'll get the single "Incorrect username or password" from chapter 1, the same reply whether or not the account exists.

## Gate a route of your own

`/me` is built in, but the point of auth is protecting *your* routes. You do that with one dependency:

```python
from fastapi import Depends
from crudauth import Principal

@app.get("/dashboard")
async def dashboard(user: Principal = Depends(auth.current_user())):
    return {"id": user.user_id, "via": user.transport}
```

`auth.current_user()` is a **dependency factory**: you call it (note the parentheses) and it hands back a FastAPI dependency. With no arguments it means "any authenticated user." If the request carries a valid credential, your handler runs with a `Principal` in hand. If it doesn't, the dependency raises `401` before a line of your code runs. You never read a cookie or decode a token yourself.

<p align="center">
  <img src="../assets/diagrams/request-flow-light.png#only-light" alt="A request's path: 1 the request carries a cookie or token or nothing, 2 the transport validates it and the CSRF header and resolves the user, 3 the resolved Principal is cached on request.state, 4 the gates check superuser and scopes before the handler runs; authentication happens once per request and is shared across every gate" width="100%">
  <img src="../assets/diagrams/request-flow-dark.png#only-dark" alt="A request's path: 1 the request carries a cookie or token or nothing, 2 the transport validates it and the CSRF header and resolves the user, 3 the resolved Principal is cached on request.state, 4 the gates check superuser and scopes before the handler runs; authentication happens once per request and is shared across every gate" width="100%">
</p>

Each request walks that path once. The transport validates the credential (and, on a mutation, the CSRF header), resolves the user, and caches the `Principal` on `request.state`, so stacking several gates on one route doesn't authenticate it four times over.

## What the Principal carries

That `Principal` is the object chapter 0 promised: one identity, whatever transport delivered it. It's a small frozen dataclass. `user_id` is the user's primary key, and `user` is the loaded `User` row, your ORM object. `transport` says which mechanism authenticated the request (`"session"` here). `is_superuser` and `email_verified` are the two flags from chapter 0's Principal. `scopes` holds capability scopes, empty for sessions and filled in by chapter 5.

Your route reads identity off the `Principal` and nothing else. It never asks "was this a cookie or a token," which is exactly why adding a bearer transport in chapter 5 won't touch this handler.

The same `current_user()` is also where authorization lives, and the gates check the fields you just saw. Each gate is a keyword:

```python
auth.current_user(superuser=True)            # must hold the superuser flag
auth.current_user(verified=True)             # must have a verified email
auth.current_user(scopes=["billing:write"])  # must carry these scopes
```

A failed gate is a `403`; a missing credential is a `401`. We'll reach for these as later chapters need them; for now, the bare `current_user()` is the whole tool.

## What you didn't have to write

Stop at fifteen lines and notice what's already handled: passwords are bcrypt-hashed (chapter 0); the login error is uniform and constant-time (chapter 1); repeated failures trip the lockout (chapter 1); session cookies carry a CSRF token that mutations must echo back (chapter 0). None of it shows up in your code, because the safe version is the default.

We leaned on `AuthUserMixin` and only gestured at the harder cases; chapter 3 makes the user model fully yours, including fitting it onto a table you don't control.

---

[Next: Modeling your user →](3-modeling-your-user.md){ .md-button .md-button--primary }
