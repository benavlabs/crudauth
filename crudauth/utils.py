"""Cross-cutting helpers: password hashing, email normalization, request IP."""

from __future__ import annotations

import base64
import functools
import hashlib
import secrets
from typing import overload

import bcrypt
from fastapi import Request

__all__ = [
    "get_password_hash",
    "verify_password",
    "dummy_verify_password",
    "make_unusable_password",
    "is_unusable_password",
    "canonical_email",
    "canonical_identifier",
    "mask_email",
    "get_client_ip",
]


def _bcrypt_input(password: str) -> bytes:
    """Pre-hash to a fixed-size token so bcrypt's 72-byte ceiling never truncates.

    bcrypt silently ignores input past 72 bytes, which would make two long
    passwords sharing a 72-byte prefix interchangeable. SHA-256 then base64
    yields a 44-byte value (well under 72) that depends on the whole password,
    so the bcrypt comparison covers every byte the user typed.
    """
    digest = hashlib.sha256(password.encode()).digest()
    return base64.b64encode(digest)


def get_password_hash(password: str) -> str:
    """Hash a plaintext password with bcrypt (random salt per call).

    The password is SHA-256 pre-hashed before bcrypt (see [_bcrypt_input]
    [crudauth.utils._bcrypt_input]), so there is no effective length ceiling and
    no silent truncation.
    """
    hashed: bytes = bcrypt.hashpw(_bcrypt_input(password), bcrypt.gensalt())
    return hashed.decode()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash.

    Returns ``False`` (rather than raising) when the stored hash is malformed,
    so a corrupted row produces a clean "invalid password" path instead of a
    500 - which would both leak information and be a DoS lever.
    """
    try:
        return bcrypt.checkpw(_bcrypt_input(plain_password), hashed_password.encode())
    except (ValueError, TypeError):
        return False


@functools.cache
def _dummy_hash() -> str:
    """A real bcrypt hash of a random value, computed once and cached.

    Used to equalize login timing: see [dummy_verify_password]
    [crudauth.utils.dummy_verify_password].
    """
    return get_password_hash(secrets.token_urlsafe(32))


def dummy_verify_password(plain_password: str) -> None:
    """Run a throwaway bcrypt verification and discard the result.

    Called on the user-not-found branch of login so the absent-user path pays
    the same bcrypt cost as the existing-user path; without it, a missing
    account returns measurably faster and becomes a user-enumeration oracle.
    """
    verify_password(plain_password, _dummy_hash())


def make_unusable_password() -> str:
    """Return a sentinel that no input can ever verify against.

    Used for OAuth-only accounts. The leading ``!`` makes the value an invalid
    bcrypt hash, so [verify_password][crudauth.utils.verify_password] always returns ``False`` for it. The
    random suffix makes every sentinel unique. Mirrors Django's
    ``set_unusable_password``.
    """
    return "!" + secrets.token_urlsafe(16)


def is_unusable_password(hashed_password: str) -> bool:
    """Whether ``hashed_password`` is the unusable sentinel (or empty).

    ``True`` means the account has no real password set - an OAuth-only account
    (see [make_unusable_password][crudauth.utils.make_unusable_password], whose
    sentinel starts with ``!``, never a valid bcrypt hash).
    """
    return not hashed_password or hashed_password.startswith("!")


@overload
def canonical_email(email: str) -> str: ...
@overload
def canonical_email(email: None) -> None: ...
def canonical_email(email: str | None) -> str | None:
    """Normalize an email for storage/comparison (trim + lowercase).

    Ensures a user created via Google as ``Foo@x.com`` can log in by password as
    ``foo@x.com`` without surprises.
    """
    if email is None:
        return None
    return email.strip().lower()


def mask_email(email: str) -> str:
    """Mask an email for display: ``john@example.com`` -> ``j***@example.com``.

    A display helper for shoulder-surfing / casual logs - **not** a security
    control (it's obfuscation, not a guarantee). Returns ``"***"`` when there's
    no ``@``; keeps only the first local-part character (so a single-char local
    part can't leak more than that one character).

    Example:
        ```python
        mask_email("john@example.com")  # "j***@example.com"
        mask_email("a@x.io")            # "a***@x.io"
        mask_email("not-an-email")      # "***"
        ```
    """
    if not email or "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    if len(local) <= 1:
        return f"{local}***@{domain}"
    return f"{local[0]}***@{domain}"


def canonical_identifier(identifier: str) -> str:
    """Normalize a login identifier the same way the user lookup does.

    Email identifiers are canonicalized (trim + lowercase) so that case variants
    of one address (``v@x.com``, ``V@x.com``) collapse to a single rate-limit /
    lockout key; otherwise an attacker could reset the per-username counter just
    by varying the case while still hitting the same account. Usernames (no
    ``@``) are left as-is, matching ``get_by_username`` which is case-sensitive.
    """
    return canonical_email(identifier) if "@" in identifier else identifier


def get_client_ip(request: Request, trusted_hops: int = 0) -> str:
    """Resolve the client IP with a trusted-proxy boundary.

    ``X-Forwarded-For`` is client-controllable at its left end, so honoring it
    blindly lets an attacker forge a fresh IP per request and slip every per-IP
    rate limit and lockout. This function only consults the header when the app
    declares how many trusted proxies sit in front of it.

    Args:
        request: The incoming request.
        trusted_hops: Number of trusted reverse proxies in front of the app.
            ``0`` (default) ignores forwarding headers entirely and uses the
            socket peer - correct when the app is directly exposed. ``N`` trusts
            the ``N`` right-most ``X-Forwarded-For`` entries as your proxies and
            returns the entry just left of them (clamped to the left-most entry
            if the chain is shorter), which an attacker prepending fake values
            cannot reach.

    Returns:
        The resolved client IP, or ``"unknown"`` if it cannot be determined.

    Example:
        ```python
        # App behind a single trusted reverse proxy (e.g. nginx, Caddy):
        CRUDAuth(..., trusted_proxy_hops=1)
        ```
    """
    if trusted_hops > 0:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            parts = [p.strip() for p in forwarded.split(",") if p.strip()]
            if parts:
                return parts[-min(trusted_hops, len(parts))]
    if request.client is not None:
        return request.client.host
    return "unknown"
