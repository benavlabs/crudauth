# Two-factor authentication (TOTP)

Opt-in authenticator-app codes. Needs `pip install "crudauth[mfa]"` (cryptography) and the MFA columns.

```python
from crudauth import CRUDAuth, MfaConfig, make_auth_identity

class User(Base, make_auth_identity(mfa=True)):   # + totp_secret_encrypted, totp_confirmed_at,
    __tablename__ = "users"                       #   totp_last_step, mfa_recovery_codes

auth = CRUDAuth(..., mfa=MfaConfig(
    issuer="Acme",                                     # shown in the authenticator app
    encryption_key=os.environ["MFA_ENCRYPTION_KEY"],  # Fernet key; list = rotation (first encrypts)
    required=lambda user: user.is_superuser,           # False (default) | True | sync/async predicate
    oauth=False,                                       # default: an OAuth login skips the second factor
))
```

Startup raises if a column is missing (map with `column_map=`), the key isn't a Fernet key, or it equals
`SECRET_KEY`. The service is `auth.mfa` (`MfaService`); `None` without `mfa=`.

## Login

- An enrolled account (or a required one) gets `{"mfa_required": true, "challenge", "expires_in"}` from
  `/login` / `/token` instead of a credential; a required, unenrolled account also gets
  `setup: {"secret", "otpauth_uri"}` (the pending secret is reused if the login is retried, until a
  password reset or change discards it). Enrolling at login trusts the password.
- `POST /mfa/verify {"challenge", "code"}` issues what the login started (session cookies or tokens) via
  the transport's `complete_login`; after setup it adds `recovery_codes`; `on_after_login` fires here.
- Challenges: hashed in the session store, `challenge_ttl_seconds` (300), single use, dead after
  `max_code_attempts` (5) wrong codes. Wrong codes count against the login lockout; a correct password
  neither clears it nor counts against it (`LockoutPolicy.forget_attempt`), a correct code clears it. Session challenges refuse `Sec-Fetch-Site: cross-site`. A
  password reset or change (`token_version` bump) voids an outstanding challenge.
- Codes: 6 ASCII digits (spaces ignored), 30 s steps, ±1 step drift, constant-time; a step is claimed
  atomically (`repo.claim_totp_step`), so no replay, even concurrently. A recovery code works in place
  of a code.
- `required` applies at password login (and OAuth with `oauth=True`); existing sessions/refresh tokens keep
  working. Enabling MFA doesn't sign out other sessions (revoke them in `on_after_mfa_enabled`).
- OAuth: an OAuth claim of an unverified account removes its MFA enrollment. Skipped unless `MfaConfig(oauth=True)`,
  even for `required` accounts (startup warns); then the callback returns the challenge (JSON) or
  redirects to `oauth_default_redirect#mfa_challenge=...` (default `redirect_base_url`) (strip it from history with
  `history.replaceState`). `POST /mfa/challenge {"challenge"}` returns `setup` details; the verify
  response carries `redirect_to`.
- A hand-written login: `authenticate_password(..., record_success=False)`, then
  `auth.mfa.challenge_login(db, user, request=..., transport="session", lockout_identifier=...,
  options={...})`; `None` means no MFA for this account (lockout already cleared).

## Account routes (authenticated, `mfa_manage` limit per user)

| Route | Body | Result |
|---|---|---|
| `GET /mfa` | | `{"enabled", "required", "recovery_codes_remaining"}` |
| `POST /mfa/totp/setup` | `{"password"}` (if the account has one) | `{"secret", "otpauth_uri"}` |
| `POST /mfa/totp/confirm` | `{"code"}` | `{"recovery_codes"}` (shown once) |
| `POST /mfa/totp/disable` | `{"code"}` (TOTP or recovery) | `403` when required |
| `POST /mfa/recovery-codes/regenerate` | `{"code"}` | new `{"recovery_codes"}` |

Admin reset without a code: `await auth.mfa.disable(db, user)`. Sudo with a code:
`await auth.sudo.elevate(principal, code=..., db=db, request=request)`.

Hooks: `on_after_mfa_enabled`, `on_after_mfa_disabled`, `on_after_recovery_code_used` (`user, db, context`).
The TOTP secret and recovery-code hashes are never in the hook `user` dict. Secrets are Fernet-encrypted
at rest (tampered ciphertext fails closed); recovery codes are SHA-256 hashes.
