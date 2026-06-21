# API Reference

Every public symbol in CRUDAuth, generated from the source docstrings. Unless a page notes
otherwise, each is importable straight from the top-level `crudauth` package.

!!! tip "New here?"
    Start with [Why CRUDAuth?](../why-crudauth.md) and the [Quick Start](../#quick-start),
    then come back for the details.

## Core

| Page | What's in it |
|---|---|
| [Endpoints](endpoints.md) | Every HTTP route CRUDAuth can mount, by area, and what gates each. |
| [CRUDAuth](crud-auth.md) | The composition root. Configure transports, mount routers, and build the `current_user()` / `rate_limit()` / `require_sudo()` route guards. |
| [Principal](principal.md) | The identity object every transport returns. |
| [Core types](core.md) | `CookieConfig`, `AuthContext`, `AuthRuntime`. |

## Transports

| Page | What's in it |
|---|---|
| [Transports](transports.md) | The `Transport` port, the built-in `SessionTransport` and `BearerTransport`, and the `SessionManager` behind server-side sessions. |

## Accounts & flows

| Page | What's in it |
|---|---|
| [OAuth](oauth.md) | Credentials, the provider port and factory, and account linking. |
| [Email](email.md) | `EmailConfig`, the `EmailSender` port, and `EmailFlowService`. |
| [Hooks](hooks.md) | `AuthHooks` lifecycle callbacks and `HookContext`. |
| [Sudo](sudo.md) | `SudoConfig` and `SudoManager` for re-authentication. |

## Data layer

| Page | What's in it |
|---|---|
| [UserRepository](repository.md) | The logical-field to column adapter over your model. |
| [Models](models.md) | `AuthUserMixin`. |

## Infrastructure

| Page | What's in it |
|---|---|
| [Rate limiting & lockout](ratelimit.md) | `RateLimit`, `KeyBy`, `LockoutPolicy`, and the limiter backends. |
| [Storage](storage.md) | The session/CSRF/token store port and its memory and Redis backends. |

## Errors & helpers

| Page | What's in it |
|---|---|
| [Exceptions](exceptions.md) | The HTTP exception hierarchy. |
| [Utilities](utils.md) | Password hashing, email normalization, client IP, and display masking. |
