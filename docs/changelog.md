# Changelog

Notable changes to CRUDAuth, newest first. CRUDAuth is pre-1.0, so minor versions may include
breaking changes; those are called out explicitly.

___

## 0.6.0 - 2026-06-21

CRUDAuth as a toolbox. The hardened auth flows that used to live only inside the route handlers
are now reusable primitives, the wired services are all reachable off `auth`, and the building
blocks are exported from the package root - so you can hand-roll a login, mint a token in a
webhook, or skip the routes entirely without losing the hardening. Everything is additive.

#### Added
- **`auth.authenticate_password(db, identifier, password, *, request)`** - the credential check
  behind `/login` and `/token` (shared escalating lockout, timing-equalized verification,
  disabled-account check), now a callable primitive on `CRUDAuth` and `AuthRuntime`. `/login` and
  `/token` were de-duplicated onto it.
- **`auth.issue_tokens(user, *, scopes=None)`** (and `BearerTransport.issue_tokens`) - the bearer
  issuance behind `/token`, with scope clamping and the `token_version` epoch. Reach for it instead
  of bare `create_access_token`, which skips both. `/token` issues through it; `/refresh` shares the
  underlying access-token minting.
- **`auth.emails`** (the `EmailFlowService`) and **`auth.oauth`** (the `OAuthAccountService`)
  accessors, `None` when unconfigured - matching `auth.repo` / `auth.sessions` / `auth.sudo`.
- **Building blocks exported** from `crudauth`: `UserRepository`, `SessionManager`, `SudoManager`,
  `EmailFlowService`, `OAuthAccountService`, and the password helpers `get_password_hash`,
  `verify_password`, `is_unusable_password`, `make_unusable_password`. (Raw token-mint functions
  stay unexported on purpose - use `issue_tokens` so the clamp and epoch come along.)
- A **"Use the building blocks"** cookbook recipe, and an end-to-end test suite against real
  Postgres (testcontainers) covering the login / token / refresh / lockout / revocation paths.

No breaking changes.

___

## 0.5.0 - 2026-06-21

Account & device management. The session/device endpoints apps kept hand-writing are now opt-in
built-in routes, plus an in-session password change. Everything is additive.

#### Added
- **Session & CSRF management routes** (`SessionTransport(management_routes=True)`, off by default):
  `GET /sessions` (device list), `DELETE /sessions/{id}` (revoke one, ownership-checked, `404` if not
  found or not yours), `POST /logout-all` (with `?keep_current=true`), and `POST /csrf/refresh`
  (re-mint a lost CSRF cookie; self-heals; the deliberate non-`current_user` recovery path). Thin
  handlers over the existing `SessionManager`; the three mutating ones enforce CSRF via the session
  transport.
- **`POST /change-password`** (always mounted): change a known password while signed in. The current
  password is the re-authentication; a successful change bumps `token_version` and revokes the user's
  *other* sessions (keeping the current one), and fires `on_after_password_changed`. `401` on a wrong
  current password, `400` on an OAuth-only account (use `/set-password`).
- **`on_after_password_changed`** hook, distinct from `on_after_password_reset` (the token flow).
- **`SessionInfo`** is now exported (the `GET /sessions` response model), and a flat **Endpoints**
  API-reference page maps every mountable route in one place.
- `SessionManager.set_csrf_cookie(...)` (the CSRF half of `set_session_cookies`, reusable on its own).

___

## 0.4.0 - 2026-06-21

Custom email bodies. `EmailSender.send` now receives an `EmailContext`, so you render your own
branded HTML for the verify / reset / change emails instead of delivering crudauth's plain text.

#### Added
- **`EmailContext` on `EmailSender.send`:** the sender now gets the assembled `link` (the token
  embedded in the URL), `kind`, `recipient`, and `expires_in`, so it can build a real HTML template
  without parsing the link out of `body`. The context carries crudauth-owned render data only -
  never the bare token, never user-controlled fields - so a sender that drops it into HTML can't be
  an XSS or credential-leak vector. `context.link` is the same assembled URL as in `body` (one
  source). Per-user personalization (`Hi Alice`) stays a `DeliveryChannel` concern (it has the `db`
  handle and owns escaping).
- **Bundled library skill** (`crudauth/.agents/skills/crudauth/`): crudauth now ships an embedded
  [library skill](https://library-skills.io), so AI coding agents follow crudauth's actual conventions
  and gotchas (account shapes, gates, recovery, custom email bodies, production wiring) in sync with the
  installed version. It travels in the wheel; install it into your project's agent with
  `uvx library-skills` (add `--claude` for Claude Code).

#### Breaking changes
- **`EmailSender.send` gains a required `context` parameter.** Add it to your `send` signature
  (`async def send(self, *, to, subject, body, kind, context)`); behavior is unchanged because
  `body` is still the pre-rendered plain-text fallback, so a sender that ignores `context` produces
  the same email as before.

___

## 0.3.0 - 2026-06-20

Account shapes. CRUDAuth's identity and recovery are now read from your model instead of assumed
to be email, so an app can log in by username, recover by phone, or hold no email at all, with the
same flows and the same security. Plus pluggable delivery channels, a server-side provisioning
seam, and a ten-recipe cookbook.

#### Added
- **Model-driven identity contract** (`make_auth_identity()` + `IdentityConfig`): the account
  *shape* is read from the model and the *intent* (login order, recovery factor) is declared in
  `IdentityConfig`, validated against the model at construction. Username-only accounts (no email)
  and non-email recovery become configuration, not forks.
- **Recovery-factor verification:** "verified" now means the contract's recovery factor is proven
  controlled, with email as the special case. A phone-recovery app verifies and resets over SMS,
  and `current_user(verified=True)` gates on the recovery factor. The verify and reset request
  endpoints are shaped to the factor, so a phone app drives them with `{"phone": ...}`.
- **Pluggable delivery channels** (`DeliveryChannel` port, `channels=[...]`): recovery tokens
  route over email, SMS, push, or any medium you implement; email is a built-in channel and every
  channel fires best-effort.
- **Provisioning seam** (`new_user_fields` / `new_user_defaults`): set app-owned columns on new
  users from a server-built context, on both `/register` and OAuth signup, gated so a client can't
  reach a privileged column.
- A **Cookbook** of ten from-scratch recipes (the three account shapes, OAuth, token APIs,
  existing-table onboarding, production), an Identity API reference page, and a refreshed
  architecture page.

#### Changed
- `current_user(verified=True)` gates on `recovery_verified` (which equals `email_verified` for an
  email-recovery app) and raises at construction when the contract has no recovery factor.
- The recovery `verify` / `reset` request bodies are generated for the recovery factor; the
  change-email endpoints mount only when the model has an `email` column.
- A non-email recovery factor emits a `{factor}_verified` bookkeeping column (e.g. `phone_verified`)
  alongside the app-declared factor column.

#### Breaking changes
- **`AuthHooks.on_after_email_verified` → `on_after_recovery_verified`.** The verification hook is
  factor-neutral now; `on_after_email_changed` keeps its name (it proves a real email). Apps
  registering the old hook must rename it.
- **`EmailFlowService.request_email_verification` / `confirm_email_verification` →
  `request_recovery_verification` / `confirm_recovery_verification`**, and the verify / reset
  request methods take a factor `value` instead of `email`. The service is constructed internally,
  so most apps are unaffected; direct callers must update.
- **Login resolves against the contract's `login` fields**, replacing the `@`-in-identifier
  heuristic. The default (email + username) behaves the same.

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
