# Changelog

Notable changes to crudauth, newest first. crudauth is pre-1.0, so minor versions may include
breaking changes; those are called out explicitly.

___

## 0.2.1 - 2026-06-15

#### Changed
- `crudauth.__version__` is now read from the installed package metadata rather than
  hardcoded, so it can't drift from `pyproject.toml`.

___

## 0.2.0 - 2026-06-15

A security and correctness pass over the extracted code, plus two capabilities the review
surfaced as missing. Pre-beta, so fixes were made directly rather than behind shims.

#### Added
- **Sudo mode** (`sudo=SudoConfig()` + `auth.require_sudo()`): short-lived re-authentication
  for sensitive actions, stamped on the session, with its own lockout and an `on_after_sudo`
  hook.
- **`POST /set-password`** for OAuth-only accounts to establish a first password while
  authenticated.
- **Token revocation** for bearer tokens via a `token_version` epoch, bumped on password reset.
- Atomic storage primitives (`set_if_absent` / `get_and_delete`) and an atomic
  `increment_and_refresh_ttl` on the rate-limiter backend.
- Startup warning when an in-memory backend is active under what is likely a multi-worker
  deployment.

#### Changed / fixed
- **Login hardening:** trusted-proxy IP resolution (`trusted_proxy_hops`), lockout-key
  canonicalization, timing-equalized verification (closes a user-enumeration oracle), and a
  SHA-256 pre-hash so bcrypt no longer truncates at 72 bytes.
- **Escalating lockout** now re-arms its round TTL atomically, and a new `on_login_success`
  knob controls what a good login clears.
- **OAuth:** `state` is bound to the initiating browser (blocks login CSRF), the redirect
  target is hardened against open redirects, callback failures degrade gracefully, and a
  missing `{provider}_id` column fails fast at startup.
- **Email:** verify / reset / change consume tokens through the atomic one-time primitives;
  trigger emails are best-effort; the "existing account" notice is throttled.
- Repackaged into feature slices (`register/` is now a package) with a documented
  import-direction architecture, and the test suite was reorganized into source-mirroring
  subpackages.

#### Breaking changes
- **`/register` is a strict allowlist.** Model columns are dropped unless named in
  `register_extra_fields`.
- **Email endpoints renamed:** `/email/verify-request`, `/email/verify-confirm`,
  `/password/reset-request`, `/password/reset-confirm`, `/email/change-request`,
  `/email/change-confirm`.
- **`token_version` column added** to `AuthUserMixin`; a persisted schema needs the migration
  (or a `column_map` entry) before bearer-token revocation works.
- **`check=` now denies on `False`** instead of ignoring the return value.
- **Disabled accounts** return the generic `"Incorrect username or password"` (was a distinct
  error).
- **Bearer scopes are clamped** to a grantable ceiling; tokens can't self-grant scopes.
- **Storage and rate-limiter ports gained required methods**; custom backends must implement
  `set_if_absent` / `get_and_delete` and `increment_and_refresh_ttl`.
- **Removed:** `OAuthToken`, `SessionData.is_active`, and the single-argument
  `get_client_ip(request)` signature (now `get_client_ip(request, trusted_hops=0)`).

___

## 0.1.0 - 2026-06-13

#### Added
- Initial release, extracted from FastroAI into a standalone, transport-agnostic
  authentication library for FastAPI.
- One `CRUDAuth` object wiring session and bearer transports to a single `Principal`, OAuth
  (Google / GitHub / custom), email flows, login lockout, rate limiting, pluggable
  memory/redis backends, lifecycle hooks, and a `column_map` over your own SQLAlchemy model.
