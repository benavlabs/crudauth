# Getting started

This is the whole process, once: install CRUDAuth, point it at your user model, mount the
router, and make your first authenticated request. The guides build on this and only show the
config specific to each feature.

## Install

=== "pip"

    ```bash
    pip install crudauth
    ```

=== "uv"

    ```bash
    uv add crudauth
    ```

OAuth, Redis, and device parsing are extras: `pip install "crudauth[all]"`.

## Your user model

Inherit `AuthUserMixin` to get the columns CRUDAuth needs; add your own freely.

```python title="models.py"
from sqlalchemy.orm import Mapped, mapped_column
from crudauth.models import AuthUserMixin
from myapp.db import Base

class User(Base, AuthUserMixin):
    __tablename__ = "users"
    full_name: Mapped[str | None] = mapped_column(default=None)
```

Already have a `users` table with different names? Map the contract instead of renaming it
with `column_map={"id": "account_id", "email": "email_address", ...}`.

## Wire it up

`CRUDAuth` takes your DB session dependency, your model, and a secret. Mounting its router is
what creates the endpoints.

```python title="main.py"
from fastapi import FastAPI
from crudauth import CRUDAuth
from myapp.db import get_session   # your dependency that yields an AsyncSession
from myapp.models import User

auth = CRUDAuth(session=get_session, user_model=User, SECRET_KEY="change-me")

app = FastAPI()
app.include_router(auth.router)   # mounts /register, /login, /logout, /me
```

Sessions are the default, so you already have cookie auth, CSRF, and login lockout. Run it
with `uvicorn main:app`.

## Your first request

```bash
# create an account
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "username": "alice", "password": "hunter2..."}'

# log in (sets the session + CSRF cookies), saving them to a cookie jar
curl -X POST http://localhost:8000/login -c jar.txt -d "username=alice&password=hunter2..."

# call an authenticated route
curl http://localhost:8000/me -b jar.txt
```

## Protect your own routes

```python
from fastapi import Depends
from crudauth import Principal

@app.get("/dashboard")
async def dashboard(user: Principal = Depends(auth.current_user())):
    return {"id": user.user_id}
```

## Next steps

- [Guides](guides/index.md): protecting routes, sessions, bearer tokens, OAuth, email, and more.
- [API Reference](api/index.md): every public symbol.

[Browse the guides →](guides/index.md){ .md-button .md-button--primary }
