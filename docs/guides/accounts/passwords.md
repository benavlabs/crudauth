# Passwords

How crudauth stores passwords, lets an OAuth-only user set one, and resets a forgotten one.

Storage and `POST /set-password` come with the base app; the reset flow additionally needs
email configured:

```python
auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY="change-me",
    email=EmailConfig(sender=MySender(), frontend_url="https://app.example.com"),  # for reset
)
app.include_router(auth.router)   # adds /set-password and /password/reset-*
```

See [Getting started](../../getting-started.md) for the base app and [Email flows](email.md)
for the sender.

## Storage

Passwords are hashed with bcrypt, after a SHA-256 pre-hash so bcrypt's 72-byte ceiling never
silently truncates a long password. Verification returns `False` for a malformed stored hash
instead of raising, so a corrupted row is a clean "invalid password", not a 500. You never
handle the plaintext beyond the route that receives it.

`MIN_PASSWORD_LENGTH` (8) is enforced on registration and on password reset. A custom
`register_schema` governs its own field constraints.

## Setting a password on an OAuth-only account

A user who signed up through OAuth has no usable password (the stored value is an unusable
sentinel). `POST /set-password` is a built-in route that lets them set their first one while
authenticated. The active session is the re-authentication, since there's no current password
to check.

```bash
# 1. set the password (the OAuth session cookie + CSRF header authenticate the call)
curl -X POST http://localhost:8000/set-password \
  -H "X-CSRF-Token: <token>" -H "Content-Type: application/json" \
  -b "session_id=<cookie>" \
  -d '{"new_password": "a-strong-one"}'

# 2. the account can now log in by password too
curl -X POST http://localhost:8000/login \
  -d "username=alice&password=a-strong-one"
```

This is **set**, not change: it refuses with `400` if the account already has a usable
password (use the reset flow to change an existing one), and it doesn't evict other sessions,
because establishing a first credential isn't a compromise response.

## Resetting a forgotten password

A user who can't log in uses the email reset flow: `POST /password/reset-request` sends a
link, and `POST /password/reset-confirm` sets the new password. See [Email flows](email.md)
for the setup. The reset also bumps `token_version`, so any bearer tokens issued before the
reset stop working.

---

[Next: Devices & sessions →](session-management.md){ .md-button .md-button--primary }
