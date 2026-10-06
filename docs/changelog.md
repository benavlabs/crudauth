# Changelog

Notable changes to CRUDAuth, newest first. CRUDAuth is pre-1.0, so minor versions may include
breaking changes; those are called out explicitly.

___

## 0.7.4 - 2026-10-05

An OAuth sign-in on a disabled account was refused, but only after the account had been linked to
the provider, and claimed if its email was unverified. It is now refused before anything is
written. No breaking changes.

#### Fixed
- **An inactive account is refused before linking.** `OAuthAccountService.get_or_create_user` now
  raises `OAuthAccountException` with `account_inactive` when the account it resolves, by provider
  id or by email, has `is_active` false. Before, an email match ran the link first: the provider id
  was written onto the account and, when its email was unverified, the account was claimed (password
  made unusable, MFA removed, `token_version` bumped, sessions ended, email marked verified). The
  callback then reported `account_inactive`, so the user saw the refusal but the account had
  already changed. An app that disables an account to keep it as it was, or soft-deletes users
  behind an `is_active` property, now gets that. An app calling `get_or_create_user` from its own
  callback gets the exception instead of the user.

#### Documentation
- The OAuth guide says nothing is written to a refused account, and shows how a soft-deleting app
  maps its flag onto `is_active` with a property.

___

## 0.7.3 - 2026-10-05

An app that isn't served at the root of `redirect_base_url` can now say where a redirect-mode OAuth
callback lands when it has nowhere else to go. No breaking changes.

#### Added
- **`CRUDAuth(oauth_default_redirect=...)`**: where the callback sends the browser on failure
  (`?error=<code>`), on an MFA challenge (`#mfa_challenge=...`), and when `redirect_to` is missing or
  unsafe. A same-origin path such as `"/app/login"` or an absolute `http(s)` URL; anything else is
  refused at startup. It defaults to `redirect_base_url`, as before. `redirect_base_url` can't carry
  the app's path, because it also builds the redirect URI registered with the provider, so a
  single-page app under `/app` next to a landing page at `/` had its failed sign-ins land on the
  landing page.

___

## 0.7.2 - 2026-09-28

Guardrails for apps that register users through their own route instead of `/register`. The
allowlist has always protected crudauth's own endpoint; nothing helped an app audit the schema it
wrote itself, and accepting `email_verified` there defeats the OAuth account claim.

#### Added
- **`REGISTRATION_ALLOWED_FIELDS` and `REGISTRATION_GATED_FIELDS` are exported from the package
  root**, next to the existing `UserRepository.gated_register_fields(names)`, which answers with the
  privileged fields a set of names contains - by logical name and by mapped column, so a
  `column_map` alias is caught. An app with its own signup route can assert
  `not auth.repo.gated_register_fields(SignUp.model_fields)` in a test.

#### Documentation
- **"Registering users from your own route"** in the registration guide: what such a schema may
  declare, why the row is built field by field rather than from `**payload.model_dump()`, and why
  `email_verified` is the one that turns a careless signup into account takeover - the provider
  login finds an account that looks verified, skips the claim, and leaves the registrant's password
  working.
- The same rule in the agent skill references, in `identity.md` (the schema and the assertion) and
  `oauth.md` (that the claim only holds while `email_verified` is server-owned, and that an app
  doing its own linking has to claim as well).

___

## 0.7.1 - 2026-09-18

Two fixes that came out of moving the FastAPI boilerplate onto 0.7.0. A redirect-mode OAuth callback
now sends a failed state check back to the app like every other failure, and rate-limit headers can
now reach the responses a later dependency or the route refused. No breaking changes.

#### Added
- **`RateLimitHeadersMiddleware`** (`from crudauth.ratelimit import RateLimitHeadersMiddleware`):
  copies `X-RateLimit-Limit` and `X-RateLimit-Remaining` onto the responses that lost them because
  something after the limiter raised, such as a `401` from `current_user()`, a `404` from the route,
  or a `422` for a bad body. It only fills in missing headers, and a request no limiter counted gets
  none. It's opt-in.

#### Fixed
- **A failed OAuth state check in redirect mode redirects**: a callback with no state cookie, a
  cookie from another sign-in, or a state that's used up or expired now goes to
  `redirect_base_url?error=invalid_state`, and the state cookie is cleared. Before, it answered
  with a JSON `400` on the API's origin. JSON mode still answers `400`.
- **Several limiters on one route report the tightest**: the headers describe the limiter with the
  least remaining, since that's the one the client will hit first. Before, the last limiter to run
  overwrote the others, so a route could report a loose budget while it was about to hit a tight one.

___

## 0.7.0 - 2026-09-17

Second factors, any identity provider, and a security pass over everything that was already here.
TOTP two-factor authentication is opt-in and covers both login routes and OAuth; an OpenID Connect
provider needs only its issuer; and five hardening branches went through the OAuth linking, session,
recovery, password and rate-limit paths. The internals were split up along the way, which is the
only place anything breaks.

#### Added
- **TOTP two-factor authentication** (`mfa=MfaConfig(...)`): RFC 6238 codes with a ±1 step drift
  window, encrypted secrets (Fernet, with key rotation), hashed single-use recovery codes, and an
  atomic per-step claim so one code can't be spent twice. Seven routes under `/mfa`
  (`verify`, `challenge`, the `GET` status, `totp/setup`, `totp/confirm`, `totp/disable`,
  `recovery-codes/regenerate`), a login challenge that both `/login` and `/token` hand off to, and
  an `oauth=` switch for whether a social login must also pass the second factor. Enrollment can
  be required for a group of accounts.
- **Any OpenID Connect provider from its issuer** (`OAuthCredentials(issuer=...)`): Keycloak,
  Zitadel, Authentik, Auth0, Okta or Entra ID need no provider class. Endpoints come from
  `{issuer}/.well-known/openid-configuration` during `await auth.initialize()`, the document must
  declare the issuer it was fetched from, the issuer must be https off localhost, and client
  authentication follows what the provider advertises (`client_secret_post`, or Basic when that's
  all it takes). `GenericOIDCProvider.from_discovery(...)` builds one outside `CRUDAuth`.
- **Public OAuth clients**: `client_secret` is sent only when set, so a PKCE-only client isn't
  rejected for sending an empty one (thanks @carlosplanchon).
- **A return destination through the recovery links** (`redirect_to` on the three request endpoints):
  carried inside the signed token rather than the emailed URL, so it survives the link being opened
  on another device and there is nothing in the URL to edit. The confirm responses hand it back;
  same-origin relative paths only.
- **Configurable password policies** (`password_policy=PasswordPolicy(...)`): enforced on
  registration, set/change password, reset, and the direct service calls (thanks @emiliano-go).
- **Dynamic rate limits**: per-request limit resolution, `KeyBy.USER_OR_IP`, key callbacks that can
  read the principal, and public access to the configured backend (thanks @emiliano-go).
- **`auth.resolve_principal(request, update_activity=False)`** for middleware and other
  request-level code, sharing the per-request principal cache (thanks @emiliano-go).
- **Injected Redis clients** on `CRUDAuth` and `SessionTransport`: a client you pass stays yours and
  isn't closed on shutdown (thanks @emiliano-go).
- **A configurable OAuth router**: custom paths and a JSON response mode alongside the redirect one
  (thanks @emiliano-go).
- **`safe_redirect_path`** exported for application routes - the same same-origin check the OAuth
  callback uses (thanks @emiliano-go).
- **`auth.oauth_providers`**, the configured providers by name, and an optional `transport=` on any
  provider for a proxy, a client certificate, or a test double.

#### Security
- **OAuth account linking**: an unverified local account is claimed rather than silently linked, a
  provider that doesn't report a verified email can't link to an existing account, and the callback
  no longer leaks which addresses exist.
- **Sessions**: `/sessions` and its delete route work on opaque handles instead of raw session ids,
  sessions are bound to `token_version`, writes are compare-and-set, logout clears a bearer refresh
  cookie too, and a login the browser marks `Sec-Fetch-Site: cross-site` is refused.
- **Recovery**: tokens are bound to the account state they were minted for (a password reset dies
  when the password or recovery value changes), the previous address is notified on an email change,
  and signup stays non-enumerable.
- **Passwords**: hashing and verification run off the event loop, the unusable-password path is
  timing-equalized, and passwords are NFKC-normalized before hashing.
- **Rate limiting and lockout**: `X-Forwarded-For` is read against a trusted-proxy boundary, TTLs are
  set atomically with the counter, `clear_all` can't be used to wipe a spray, the lockout is
  configurable (`LockoutConfig`), and a correct password that still needs a second factor neither
  counts against the lockout nor clears it.

#### Changed
- `CRUDAuth.initialize()` also initializes the configured OAuth providers, which is where an OIDC
  provider resolves its endpoints. An app that never called it now needs to.
- The composition root was split up: the account and session-management routes, the rate-limit
  dependencies, the OAuth path helpers and the transports' own routes moved into their own modules,
  `utils.py` became a package, and the route builders take a typed `AuthSurface` instead of `Any`.
  Every documented import path is unchanged.

#### Breaking changes
- **`EmailFlowService.confirm_recovery_verification` / `reset_password` / `confirm_email_change`
  return `EmailFlowResult(user, redirect_to)`** instead of the user row. Unpack it, or read `.user`;
  code that ignores the return value is unaffected.
- **`DELETE /sessions/{id}` takes a session handle**, and each entry's `id` in `GET /sessions` is
  that handle (the SHA-256 of the session id) rather than the session id itself. The response shape
  is unchanged; a client that stored the old values must re-read the list.
- **Internals that moved**: `auth._apply_rate_limit` is gone (use `enforce_rate_limit` or
  `auth.rate_limit(...)`), the per-feature store attributes are one registry, `SessionInfo` is
  defined in `crudauth.transports.session.management` (importing it from `crudauth` is unchanged),
  `_shared_router` and `_add_session_management_routes` are gone, and four transport helpers dropped
  their underscore: `SessionTransport.enforce_csrf`, `BearerTransport.read_refresh`, `clamp_scopes`
  and `access_token`.
- **`AbstractOAuthProvider` gained `initialize()` and `_ensure_ready()`** (both no-ops by default)
  and an optional `transport=` argument; a subclass that passes its arguments through is unaffected.

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
