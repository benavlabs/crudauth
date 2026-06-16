<p align="center">
  <a href="https://benavlabs.github.io/crudauth">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/assets/crudauth-cover-dark.png">
      <img src="docs/assets/crudauth-cover-light.png" alt="crudauth" width="50%">
    </picture>
  </a>
</p>
<p align="center" markdown=1>
  <i><b>Batteries-included, transport-agnostic authentication for FastAPI.</b></i>
</p>

<p align="center">
<a href="https://pypi.org/project/crudauth/">
  <img src="https://img.shields.io/pypi/v/crudauth?color=%2334D058&label=pypi%20package" alt="PyPi Version"/>
</a>
<a href="https://pypi.org/project/crudauth/">
  <img src="https://img.shields.io/pypi/pyversions/crudauth.svg?color=%2334D058" alt="Supported Python Versions"/>
</a>
<a href="https://github.com/benavlabs/crudauth/blob/main/LICENSE">
  <img src="https://img.shields.io/badge/license-MIT-34D058" alt="License"/>
</a>
<a href="https://benavlabs.github.io/crudauth">
  <img src="https://img.shields.io/badge/docs-benavlabs.github.io%2Fcrudauth-34D058?logo=materialformkdocs&logoColor=white" alt="Documentation"/>
</a>
<a href="https://deepwiki.com/benavlabs/crudauth">
  <img src="https://img.shields.io/badge/DeepWiki-1F2937.svg?logo=book&logoColor=white&labelColor=1F2937&color=34D058" alt="DeepWiki"/>
</a>
</p>

<p align="center">
<a href="https://benavlabs.github.io/crudauth">Docs</a> · <a href="https://deepwiki.com/benavlabs/crudauth">DeepWiki</a> · <a href="https://discord.com/invite/TEmPs22gqB">Discord</a>
</p>

<hr>
<p align="justify">
<b>crudauth</b> gives you one <code>CRUDAuth</code> object that wires cookie sessions, JWT bearer tokens, OAuth, and email flows (verify / reset / change) - with CSRF, escalating login lockout, sudo mode, and multi-device session management - over <b>your own</b> SQLAlchemy <code>User</code> model. App policy lives in hooks, not in forked dependency code. Sessions and bearer both resolve to the same <code>Principal</code>, so narrowing or adding a transport never changes how you authorize a route.
</p>

<hr>

## Features

- **Transport-agnostic**: cookie sessions and JWT bearer tokens behind a single `Principal`; first credential present wins, and authorization code never depends on *which* transport authenticated.
- **Your model, your schema**: works over your existing SQLAlchemy `User` via a logical-field `column_map` - no forced renames, no second user table.
- **Secure by default**: synchronizer-token CSRF, escalating per-IP/per-user login lockout, bcrypt with SHA-256 pre-hash (no 72-byte truncation), timing-equalized login, and trusted-proxy IP resolution.
- **OAuth**: Google, GitHub, or a custom provider - with the `state` bound to the initiating browser to block login CSRF.
- **Email flows**: verify / reset / change - you implement the `EmailSender` port, the package mints and verifies the signed, single-use tokens.
- **Sudo mode**: short-lived re-authentication to gate sensitive actions, stamped on the session and cleared on logout.
- **Multi-device sessions**: list, revoke one, or "sign out everywhere", with a configurable per-user session cap.
- **App policy in hooks**: `AuthHooks` for welcome email, trial grant, audit logging - fired uniformly across every auth path.
- **Pluggable backends**: in-memory for dev, Redis for production - for sessions, CSRF, lockout counters, and one-time tokens.
- **Fully typed & async**: ships `py.typed`, built on SQLAlchemy 2.0 and Pydantic v2.

## Requirements

- **Python** 3.10+
- **FastAPI**, **SQLAlchemy 2.0+**, **Pydantic v2** (installed as dependencies)

## Install

```bash
pip install crudauth            # core (session + bearer)
pip install "crudauth[all]"     # + httpx (oauth), redis, user-agents
```

Or with uv:

```bash
uv add crudauth
```

## Quickstart

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

## The user model

Inherit the mixin and get every column the package needs; your own columns
coexist freely.

```python
from sqlalchemy.orm import Mapped, mapped_column
from crudauth.models import AuthUserMixin
from myapp.db import Base

class User(Base, AuthUserMixin):
    __tablename__ = "users"
    full_name: Mapped[str | None] = mapped_column(default=None)
```

Existing table with different names? Map the contract, don't rename your schema:

```python
auth = CRUDAuth(
    session=get_session, user_model=LegacyAccount, SECRET_KEY=...,
    column_map={"id": "account_id", "email": "email_address", "hashed_password": "pw_hash"},
)
```

## Protecting routes - one factory, every case a kwarg

```python
auth.current_user()                              # required, 401 if anon
auth.current_user(optional=True)                 # None instead of raising
auth.current_user(superuser=True)                # 403 unless is_superuser
auth.current_user(verified=True)                 # 403 unless email_verified
auth.current_user(scopes=["reports:read"])       # 403 unless scopes ⊇ required
auth.current_user(transport="bearer")            # narrow to one transport
auth.current_user(superuser=True, check=my_predicate)  # extra per-route check
```

The resolved `Principal` carries `user_id`, `is_superuser`, `scopes`,
`transport` (which transport authed the request), and `user` (your resolved
row).

## Multiple transports, one identity

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

When both credentials are present, the **first transport in the list wins**.
CSRF is a property of the session transport - it appears only where sessions do,
never on bearer/api-key paths.

## Storage & lifespan

Server-side backends open connections on startup - call `initialize()` /
`shutdown()` in your lifespan:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    await auth.initialize()
    yield
    await auth.shutdown()
```

## OAuth, email, hooks, sudo

See the usage cookbook for OAuth (Google / GitHub / custom providers), email
flows (implement the `EmailSender` port; the package mints/verifies the signed
tokens), lifecycle hooks (`AuthHooks` - welcome email, trial grant, audit log),
sudo mode (`sudo=SudoConfig()` + `auth.require_sudo()`), and dropping to
primitives.

## Architecture

crudauth is ports-and-adapters with feature slices and a single composition
root (`CRUDAuth`). The layering and the import-direction rules live in the
[Architecture docs](https://benavlabs.github.io/crudauth/architecture/) - read them before
adding a transport, OAuth provider, or storage backend; each is meant to be a drop-in
file, not a cross-cutting edit.

## License

[`MIT`](LICENSE)

## Contact

Benav Labs – [benav.io](https://benav.io), [Discord](https://discord.com/invite/TEmPs22gqB)

## The Benav Labs FastAPI family

crudauth is part of a family of composable FastAPI building blocks - use whichever you need:

- **[FastCRUD](https://github.com/benavlabs/fastcrud)** - powerful CRUD methods and automatic endpoint creation for your SQLAlchemy models.
- **[CRUDAdmin](https://github.com/benavlabs/crudadmin)** - a modern, secure admin interface generated straight from your models.
- **[Fastro (FastAPI-boilerplate)](https://github.com/benavlabs/FastAPI-boilerplate)** - a batteries-included FastAPI starter: auth, CRUD, jobs, caching, and rate-limits.
- **[FastroAI](https://fastro.ai)** - the complete FastAPI SaaS template: payments, entitlements, email, a frontend, and AI agents.

## Build a full SaaS on FastAPI

crudauth handles authentication in **[FastroAI](https://fastro.ai)** - the complete FastAPI SaaS template: auth, Stripe payments (subscriptions, credits, discounts), entitlements, transactional email, an Astro frontend, and PydanticAI agents, wired together and production-ready.

<p align="center">
  <a href="https://fastro.ai">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/benavlabs/FastAPI-boilerplate/main/docs/assets/fastroai-card-dark.png">
      <img src="https://raw.githubusercontent.com/benavlabs/FastAPI-boilerplate/main/docs/assets/fastroai-card-light.png" alt="FastroAI - the complete FastAPI SaaS template: auth, Stripe payments, entitlements, email, frontend and AI" width="100%">
    </picture>
  </a>
</p>

<p align="center"><b><a href="https://fastro.ai">Ship your SaaS faster with FastroAI →</a></b></p>

<hr>
<a href="https://benav.io">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/benavlabs/FastAPI-boilerplate/main/docs/assets/benav-labs-banner-dark.png">
    <img src="https://raw.githubusercontent.com/benavlabs/FastAPI-boilerplate/main/docs/assets/benav-labs-banner-light.png" alt="Benav Labs - benav.io" width="100%"/>
  </picture>
</a>
