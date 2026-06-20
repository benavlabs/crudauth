<style>
    .md-typeset h1,
    .md-content__button {
        display: none;
    }
</style>

<p align="center">
  <a href="https://github.com/benavlabs/crudauth">
    <img src="assets/crudauth-cover-light.png#only-light" alt="CRUDAuth" width="55%">
    <img src="assets/crudauth-cover-dark.png#only-dark" alt="CRUDAuth" width="55%">
  </a>
</p>
<p align="center" markdown=1>
  <i>Batteries-included, transport-agnostic authentication for FastAPI.</i>
</p>
<p align="center" markdown=1>
<a href="https://pypi.org/project/crudauth/">
  <img src="https://img.shields.io/pypi/v/crudauth?color=%2334D058&label=pypi%20package" alt="PyPi Version"/>
</a>
<a href="https://pypi.org/project/crudauth/">
  <img src="https://img.shields.io/pypi/pyversions/crudauth.svg?color=%2334D058" alt="Supported Python Versions"/>
</a>
<a href="https://github.com/benavlabs/crudauth/blob/main/LICENSE">
  <img src="https://img.shields.io/badge/license-MIT-34D058" alt="License"/>
</a>
<a href="https://deepwiki.com/benavlabs/crudauth">
  <img src="https://img.shields.io/badge/DeepWiki-1F2937.svg?logo=book&logoColor=white&labelColor=1F2937&color=34D058" alt="DeepWiki"/>
</a>
</p>
<hr>
<p align="justify">
<b>CRUDAuth</b> gives you one <code>CRUDAuth</code> object that wires cookie sessions, JWT bearer tokens, OAuth, and email flows (verify / reset / change) - with CSRF, escalating login lockout, sudo mode, and multi-device session management - over <b>your own</b> SQLAlchemy <code>User</code> model. Sessions and bearer both resolve to the same <code>Principal</code>, so narrowing or adding a transport never changes how you authorize a route, and app policy lives in <b>hooks</b> instead of forked dependency code.
</p>
<hr>

> **Status:** early `0.2` (alpha) - this is the v1 surface we're converging on. APIs may still shift before `1.0`.

## Features

- **Transport-agnostic**: cookie sessions and JWT bearer tokens behind a single `Principal`; first credential present wins, and authorization never depends on *which* transport authenticated.
- **Your model, your schema**: works over your existing SQLAlchemy `User` via a logical-field `column_map` - no forced renames, no second user table.
- **Secure by default**: synchronizer-token CSRF, escalating per-IP/per-user login lockout, bcrypt with SHA-256 pre-hash (no 72-byte truncation), timing-equalized login, and trusted-proxy IP resolution.
- **OAuth**: Google, GitHub, or a custom provider - with the `state` bound to the initiating browser to block login CSRF.
- **Email flows**: verify / reset / change - you implement the `EmailSender` port, the package mints and verifies the signed, single-use tokens.
- **Sudo mode**: short-lived re-authentication to gate sensitive actions, stamped on the session and cleared on logout.
- **Multi-device sessions**: list, revoke one, or "sign out everywhere", with a configurable per-user session cap.
- **App policy in hooks**: `AuthHooks` for welcome email, trial grant, audit logging - fired uniformly across every auth path.
- **Pluggable backends**: in-memory for dev, Redis for production - for sessions, CSRF, lockout counters, and one-time tokens.
- **Fully typed and async**: ships `py.typed`, built on SQLAlchemy 2.0 and Pydantic v2.

## Requirements

- **Python 3.10+**
- **FastAPI**, **SQLAlchemy 2.0+**, **Pydantic v2** (installed as dependencies)

## Quick Start

### 1. Install CRUDAuth

=== "pip"

    ```bash
    pip install crudauth
    ```

=== "uv"

    ```bash
    uv add crudauth
    ```

For OAuth, Redis, and device parsing, install the extras: `pip install "crudauth[all]"`.

### 2. Mount the router

Sessions are the default - no `transports=` needed. You get cookie auth, CSRF,
login lockout, secure cookies, and `/login` `/logout` `/register` `/me`.

```python
from fastapi import FastAPI, Depends
from crudauth import CRUDAuth, Principal
from myapp.db import get_session
from myapp.models import User

auth = CRUDAuth(session=get_session, user_model=User, SECRET_KEY="change-me")

app = FastAPI()
app.include_router(auth.router)

@app.get("/dashboard")
async def dashboard(me: Principal = Depends(auth.current_user())):
    return {"hello": me.user.username}
```

That's it - register a user at `POST /register`, log in at `POST /login`, and
`/dashboard` is now gated.

## Usage

### Protect any route

`current_user()` is one factory; every authorization rule is a keyword. It
returns a [`Principal`](#) carrying `user_id`, `is_superuser`, `scopes`, the
authenticating `transport`, and the resolved `user` row.

```python
auth.current_user()                          # required, 401 if anonymous
auth.current_user(optional=True)             # None instead of raising
auth.current_user(superuser=True)            # 403 unless is_superuser
auth.current_user(verified=True)             # 403 unless email_verified
auth.current_user(scopes=["reports:read"])   # 403 unless scopes are a superset
auth.current_user(transport="bearer")        # narrow to one transport
```

### One identity across transports

Add bearer tokens for your API alongside browser sessions. Both resolve to the
same `Principal`, so your route code never changes - when both credentials are
present, the **first transport in the list wins**.

```python
from crudauth import CRUDAuth, SessionTransport, BearerTransport

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY=...,
    transports=[
        SessionTransport(backend="redis", redis_url=..., csrf=True),  # browsers
        BearerTransport(access_ttl=900, refresh="cookie"),            # apps/scripts
    ],
)
```

CSRF is a property of the session transport - it appears only where sessions do,
never on bearer paths.

### Use your existing user table

Already have a `users` table with different column names? Map the contract
instead of renaming your schema:

```python
auth = CRUDAuth(
    session=get_session, user_model=LegacyAccount, SECRET_KEY=...,
    column_map={
        "id": "account_id",
        "email": "email_address",
        "hashed_password": "pw_hash"
    },
)
```

## License

[`MIT`](https://github.com/benavlabs/crudauth/blob/main/LICENSE)

## The Benav Labs family

CRUDAuth is part of a family of composable FastAPI building blocks - use whichever you need:

- **[FastCRUD](https://github.com/benavlabs/fastcrud)** - powerful CRUD methods and automatic endpoint creation for your SQLAlchemy models.
- **[CRUDAdmin](https://github.com/benavlabs/crudadmin)** - a modern, secure admin interface generated straight from your models.
- **[Fastro (FastAPI-boilerplate)](https://github.com/benavlabs/FastAPI-boilerplate)** - a batteries-included FastAPI starter: auth, CRUD, jobs, caching, and rate-limits.
- **[FastroAI](https://fastro.ai)** - the complete FastAPI SaaS template: payments, entitlements, email, a frontend, and AI agents.

## Build a full SaaS on FastAPI

CRUDAuth handles authentication in **[FastroAI](https://fastro.ai)** - the complete FastAPI SaaS template: auth, Stripe payments (subscriptions, credits, discounts), entitlements, transactional email, an Astro frontend, and PydanticAI agents, wired together and production-ready.

<p align="center">
  <a href="https://fastro.ai">
    <img src="https://raw.githubusercontent.com/benavlabs/FastAPI-boilerplate/main/docs/assets/fastroai-card-light.png#only-light" alt="FastroAI - the complete FastAPI SaaS template" width="100%">
    <img src="https://raw.githubusercontent.com/benavlabs/FastAPI-boilerplate/main/docs/assets/fastroai-card-dark.png#only-dark" alt="FastroAI - the complete FastAPI SaaS template" width="100%">
  </a>
</p>

<p align="center"><b><a href="https://fastro.ai">Ship your SaaS faster with FastroAI →</a></b></p>
