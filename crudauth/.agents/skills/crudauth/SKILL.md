---
name: crudauth
description: >
  Use when building or modifying authentication in a FastAPI app with crudauth (the `crudauth` PyPI
  package) — covers `CRUDAuth`, the `AuthUserMixin` / `make_auth_identity` user model, `IdentityConfig`,
  `current_user(...)` gates, session + bearer transports, OAuth (Google/GitHub), email verification /
  password reset / change, custom email bodies (`EmailSender` / `EmailContext` / `DeliveryChannel`),
  registration allowlists and provisioning, sudo mode, and account shapes (email, username-only, phone
  recovery). Activate when the code imports `crudauth`, defines a `CRUDAuth(...)`, a `current_user`
  dependency, an `AuthUserMixin` model, or an `EmailSender`, or when the user asks to add login /
  signup / sessions / JWT / OAuth / email verification to a FastAPI app, even without naming the library.
license: MIT
metadata:
  author: benav-labs
  package: crudauth
---

# crudauth

crudauth is transport-agnostic authentication for FastAPI over **your own** SQLAlchemy 2.0 user model.
One object is the composition root:

- **`CRUDAuth(...)`** — configure session, model, secret, transports, email, OAuth once. Mount
  `auth.router` to get the endpoints; call `auth.current_user(...)` to gate routes.
- Every transport (cookie session, bearer JWT, OAuth) resolves to one **`Principal`**, so your
  authorization code never depends on how the request authenticated.

`CRUDAuth` (capitalized) is the object you build; `crudauth` lowercase is the package/import. This
skill covers `crudauth >= 0.4`.

**The highest-value content is the [Security invariants](#security-invariants-do-not-break-these) and
[Gotchas](#gotchas) sections — read them before writing code.** Most crudauth mistakes are security
regressions (gating on the wrong flag, leaking account existence, making a privileged field settable),
not API misuse.

---

## Canonical setup

The minimal viable app. Start here, then add transports / email / OAuth as needed.

```python
# models.py — crudauth adds its columns to a model you own
from sqlalchemy.orm import Mapped, mapped_column
from crudauth.models import AuthUserMixin
from myapp.db import Base

class User(Base, AuthUserMixin):
    __tablename__ = "users"
    full_name: Mapped[str | None] = mapped_column(default=None)   # your columns ride alongside
```

```python
# main.py
import os
from fastapi import FastAPI, Depends
from crudauth import CRUDAuth, Principal
from myapp.db import get_session          # async dependency yielding AsyncSession
from myapp.models import User

auth = CRUDAuth(session=get_session, user_model=User, SECRET_KEY=os.environ["SECRET_KEY"])

app = FastAPI()
app.include_router(auth.router)            # /register, /login, /logout, /me (+ CSRF, login lockout)

@app.get("/dashboard")
async def dashboard(user: Principal = Depends(auth.current_user())):
    return {"id": user.user_id}
```

`AuthUserMixin` is the default account shape (email + username login, email recovery). `SECRET_KEY`
comes from the environment, never a literal. crudauth never opens DB connections itself — it borrows
`get_session`.

---

## Choosing the account shape

The **model is the source of truth**. `CRUDAuth` reads its columns and validates them against
`IdentityConfig` at construction (fail-closed). Pick the shape, then declare it in both places.

| Want | Model | `identity=` |
|---|---|---|
| Email + username login, email recovery (default) | `AuthUserMixin` | (omit) |
| Username-only, no email, no recovery | `make_auth_identity(identifiers=["username"], recovery=None, oauth=False)` | `IdentityConfig(login=["username"], recovery=None)` + a `register_schema` without email |
| Phone recovery (verify/reset over SMS) | `make_auth_identity(identifiers=["username"], recovery="phone", oauth=False)` + your own unique `phone` column | `IdentityConfig(login=["username"], recovery="phone")` + a `DeliveryChannel` |
| Adopt an existing `users` table | your existing model | pass `column_map={"id": "account_id", "hashed_password": "pw_hash", ...}` |

Full details, the emitted columns, and `column_map` mechanics: `references/identity.md`.

---

## Choosing the gate

`auth.current_user(...)` returns a FastAPI dependency. Combine options freely:

| Need | Gate |
|---|---|
| Any authenticated user | `current_user()` |
| Proven recovery factor (email/phone verified) | `current_user(verified=True)` |
| Admin | `current_user(superuser=True)` |
| Bearer scope | `current_user(scopes=["reports:read"])` |
| Custom rule | `current_user(check=lambda p: p.user.org_id == 1)` (denies only on `False`) |
| Allow anonymous | `current_user(optional=True)` (returns `None` instead of 401) |
| One credential kind only | `current_user(transport="session")` / `"bearer"` |

The handler receives a `Principal` (`user_id`, `scopes`, `transport`, `user`, `is_superuser`,
`email_verified`, `recovery_verified`, `metadata`). Full reference: `references/gates.md`.

---

## Transports

```python
from crudauth import SessionTransport, BearerTransport
auth = CRUDAuth(..., transports=[SessionTransport(), BearerTransport(access_ttl=900, refresh="cookie")])
```

`SessionTransport` → `/login` `/logout` (cookies + CSRF, for browsers). `BearerTransport` → `/token`
`/refresh` (JWT, for API/mobile/CLI; `refresh="body"` returns the refresh token in JSON; scopes via
`default_scopes` / `grantable_scopes`). With both, the first credential **present** wins and both
resolve to the same `Principal`, so a route's gates don't change. CSRF is automatic on the session
transport and irrelevant to bearer. See `references/transports.md`.

---

## Email, recovery, and custom bodies

```python
from crudauth import CRUDAuth, EmailConfig, EmailSender

class MySender(EmailSender):
    async def send(self, *, to, subject, body, kind, context):
        # plain: deliver `body` (crudauth's text) as-is.
        # branded HTML: build it from context.link — the assembled URL, token embedded.
        await tasks.enqueue(send_email, to=to, subject=subject, html=body)

auth = CRUDAuth(..., email=EmailConfig(sender=MySender(), frontend_url="https://app.example.com"))
```

`email=` mounts verify / reset / change. `send` receives an **`EmailContext`** (`kind`, `link`,
`recipient`, `expires_in`) — crudauth-owned render data only, so you build your own HTML from
`context.link` without parsing it out of `body`. For SMS/push, or per-user copy, implement a
`DeliveryChannel` (`deliver(intent, db)`, gets the `db` handle and user row) and pass `channels=[...]`.
Full flows, endpoints, the `kind` values, and the security rules: `references/email.md`.

---

## Registration & provisioning

`/register` is a **strict allowlist**. A column a client sends is dropped unless listed in
`register_extra_fields={"display_name"}`. For server-set columns (a default tier, a derived name),
use `new_user_defaults={...}` (constants) or `new_user_fields=callback` (derived; runs on `/register`
**and** OAuth signup). Privileged fields (`is_superuser`, `email_verified`, `token_version`, oauth ids,
the PK) are never settable through any of these.

---

## OAuth

```python
from crudauth import OAuthCredentials, SessionTransport
auth = CRUDAuth(..., transports=[SessionTransport()], redirect_base_url="https://app.example.com",
                oauth={"google": OAuthCredentials(client_id=..., client_secret=...)})
```

Adds `/oauth/{provider}/authorize` + `/oauth/{provider}/callback`. Needs a `SessionTransport`,
`redirect_base_url`, and a `{provider}_id` column (`AuthUserMixin` has the built-ins). Auto-links to an
existing account **only on a provider-verified email**. See `references/oauth.md`.

---

## Production

In-memory backends aren't shared across workers (crudauth warns at startup). Use Redis and wire the
lifespan:

```python
from crudauth.ratelimit import redis_rate_limiter
auth = CRUDAuth(..., transports=[SessionTransport(backend="redis", redis_url=REDIS_URL)],
                rate_limiter=redis_rate_limiter(REDIS_URL))

@asynccontextmanager
async def lifespan(app):
    await auth.initialize(); yield; await auth.shutdown()
```

Serve over HTTPS (session cookies are `secure` by default); set `trusted_proxy_hops=N` behind a load
balancer. See `references/production.md` for storage, lockout tuning, and sudo mode.

---

## Security invariants (do not break these)

These are the load-bearing rules. Breaking one is a vulnerability, not a style nit.

1. **Gate "verified" with `current_user(verified=True)`, never `principal.email_verified`.** The flag
   is `False` on a non-email account (username-only, phone), so `check=lambda p: p.email_verified`
   silently always-denies those apps. `verified=True` reads the contract's recovery factor.
2. **Never make email/recovery request endpoints reveal whether an account exists.** They return a
   uniform response by design (non-enumeration). A "helpful" 404 for an unknown email is a regression.
3. **`/register` must not set privileged columns.** `is_superuser`, `email_verified`,
   `{factor}_verified`, `token_version`, oauth ids, and the PK stay gated even if sent or listed in
   `register_extra_fields`. Server-set values go through `new_user_defaults` / `new_user_fields`.
4. **`EmailContext` carries no user-controlled data and no bare token.** Don't put `username`/`email`
   into email HTML via the sender — that's an XSS surface crudauth deliberately avoids. Personalize in
   a `DeliveryChannel` (it owns escaping). The token reaches the sender only embedded in `context.link`.
5. **OAuth links to an existing account only on a verified provider email.** Don't relax this; it's the
   account-takeover defense.

---

## Gotchas

1. **`EmailSender.send` takes `context` (since 0.4).** Signature is
   `send(self, *, to, subject, body, kind, context)`. An old 4-arg `send` raises `TypeError`. Render
   HTML from `context.link`; `body` stays the plain-text fallback.
2. **`current_user(verified=True)` raises at construction when `recovery=None`.** A no-recovery shape
   has nothing to prove control of, so the gate is a config error, not a silent deny.
3. **`check=` denies only on `False`.** Returning `False` is a 403; `None` or any other value does
   **not** deny. To deny with a custom status/message, raise from inside `check`.
4. **Reach the user via `Principal` / the repo, not ad-hoc attributes.** crudauth speaks logical field
   names mapped through `column_map`; a hardcoded `user.email` breaks a remapped or email-less model.
5. **A password reset evicts the user's other sessions** (bumps `token_version`, revoking bearer
   tokens). Intended attacker eviction, not a bug.
6. **Bearer scopes are clamped to `grantable_scopes`.** A token can't self-grant beyond the ceiling,
   re-checked at `/refresh`.
7. **A session cookie may never be `SameSite=None`** — rejected at construction. Bearer's refresh
   cookie may.
8. **`recovery="phone"` emits a `phone_verified` column**, but you declare the `phone` column yourself
   (unique). The factory emits the `{factor}_verified` bookkeeping flag.
9. **Username collisions are public (422 "already taken"); email collisions are not** (uniform 202).
   Username is a public namespace by design; don't "fix" the asymmetry.
10. **`SECRET_KEY` rotation invalidates every session and token.** Treat it as a managed secret.
11. **`new_user_fields` runs on OAuth signup too**, fed a server-built context (never the request
    body). Use it for columns both signup paths must set.
12. **OAuth is unavailable on an `oauth=False` model** (no `{provider}_id` columns).

---

## When to drill into references

Load on demand:

- `references/identity.md` — account shapes, `make_auth_identity`, `IdentityConfig`, the emitted
  columns, `column_map`, the recovery factor and `{factor}_verified`.
- `references/gates.md` — every `current_user(...)` option, the `Principal` shape, authorization patterns.
- `references/transports.md` — session vs bearer, `/token` `/refresh`, scopes, CSRF, multiple transports.
- `references/email.md` — `EmailConfig`, `EmailSender` + `EmailContext`, `DeliveryChannel` / `DeliveryIntent`,
  the message kinds, verify/reset/change endpoints, non-enumeration.
- `references/oauth.md` — providers, `OAuthCredentials`, account linking, `/set-password`, custom providers.
- `references/production.md` — Redis storage, lifespan, rate limiting & lockout, sudo mode, proxies, secrets.
