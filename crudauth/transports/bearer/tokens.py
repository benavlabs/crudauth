"""JWT primitives for the bearer transport and for signed email tokens.

These are pure functions - no global config. The facade threads the secret key
in. They are also exported for power users who want to mint/verify tokens by
hand (see the "drop to primitives" cookbook section).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

import jwt
from jwt import ExpiredSignatureError, PyJWTError

from ...constants import (
    DEFAULT_ACCESS_TTL_SECONDS,
    DEFAULT_ALGORITHM,
    DEFAULT_REFRESH_TTL_DAYS,
)

__all__ = [
    "TokenType",
    "create_access_token",
    "create_refresh_token",
    "verify_token",
    "is_expired_token",
    "create_signed_token",
    "verify_signed_token",
    "verify_signed_token_full",
]


class TokenType(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"


def _expiry(delta: timedelta) -> datetime:
    return datetime.now(timezone.utc) + delta


def create_access_token(
    data: dict[str, Any],
    secret_key: str,
    *,
    expires_delta: timedelta | None = None,
    algorithm: str = DEFAULT_ALGORITHM,
    scopes: list[str] | tuple[str, ...] | None = None,
) -> str:
    """Mint a short-lived access token.

    Args:
        data: Claims to encode; typically ``{"sub": <user_id>}``.
        secret_key: HMAC signing key.
        expires_delta: Lifetime; defaults to ``DEFAULT_ACCESS_TTL_SECONDS``.
        algorithm: JWT algorithm.
        scopes: Capability scopes to embed under the ``scopes`` claim.

    Returns:
        The encoded JWT string.
    """
    to_encode = dict(data)
    to_encode["exp"] = _expiry(expires_delta or timedelta(seconds=DEFAULT_ACCESS_TTL_SECONDS))
    to_encode["token_type"] = TokenType.ACCESS.value
    if scopes is not None:
        to_encode["scopes"] = list(scopes)
    return jwt.encode(to_encode, secret_key, algorithm=algorithm)


def create_refresh_token(
    data: dict[str, Any],
    secret_key: str,
    *,
    expires_delta: timedelta | None = None,
    algorithm: str = DEFAULT_ALGORITHM,
) -> str:
    """Mint a long-lived refresh token.

    Args:
        data: Claims to encode; typically ``{"sub": <user_id>, "scopes": [...]}``.
        secret_key: HMAC signing key.
        expires_delta: Lifetime; defaults to ``DEFAULT_REFRESH_TTL_DAYS`` days.
        algorithm: JWT algorithm.

    Returns:
        The encoded JWT string.
    """
    to_encode = dict(data)
    to_encode["exp"] = _expiry(expires_delta or timedelta(days=DEFAULT_REFRESH_TTL_DAYS))
    to_encode["token_type"] = TokenType.REFRESH.value
    return jwt.encode(to_encode, secret_key, algorithm=algorithm)


def verify_token(
    token: str,
    secret_key: str,
    expected_token_type: TokenType,
    *,
    algorithm: str = DEFAULT_ALGORITHM,
) -> dict[str, Any] | None:
    """Decode and validate an access/refresh token.

    Args:
        token: The encoded JWT.
        secret_key: HMAC key the token was signed with.
        expected_token_type: The required ``token_type`` claim (access vs refresh).
        algorithm: JWT algorithm.

    Returns:
        The decoded claims dict, or ``None`` for any failure (bad signature,
        expiry, wrong type, missing ``sub``). Callers that must tell an *expired*
        token apart from a *tampered* one (the bearer transport, to fall through
        rather than hard-fail) pair this with
        [is_expired_token][crudauth.transports.bearer.tokens.is_expired_token].
    """
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
    except PyJWTError:
        return None
    if payload.get("token_type") != expected_token_type.value:
        return None
    if payload.get("sub") is None:
        return None
    return payload


def is_expired_token(token: str, secret_key: str, *, algorithm: str = DEFAULT_ALGORITHM) -> bool:
    """Whether ``token`` fails to verify *solely* because it has expired.

    A correctly-signed, well-formed token that is merely past its ``exp`` returns
    ``True``; a tampered or bad-signature token returns ``False`` (the signature
    is checked before expiry, so a forged-and-expired token does not slip
    through as "just expired"). Lets the bearer transport treat an expired access
    token as an absent credential - falling through to the next transport or to
    anonymous - while still hard-failing a tampered one.

    Args:
        token: The encoded JWT.
        secret_key: HMAC key the token was signed with.
        algorithm: JWT algorithm.

    Returns:
        ``True`` if the only verification failure is expiry, else ``False``.
    """
    try:
        jwt.decode(token, secret_key, algorithms=[algorithm])
    except ExpiredSignatureError:
        return True
    except PyJWTError:
        return False
    return False


def create_signed_token(
    secret_key: str,
    user_id: Any,
    purpose: str,
    *,
    expires_hours: int = 24,
    algorithm: str = DEFAULT_ALGORITHM,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """Mint a purpose-scoped signed token (email verify / password reset / email change).

    Args:
        secret_key: HMAC signing key.
        user_id: Subject the token authorizes (stored as ``sub``, stringified).
        purpose: Scopes the token to one flow (e.g. ``"reset_password"``);
            [verify_signed_token][crudauth.transports.bearer.tokens.verify_signed_token] requires the same value.
        expires_hours: Lifetime in hours.
        algorithm: JWT algorithm.
        extra_claims: Additional claims to embed (e.g. ``{"new_email": ...}``).

    Returns:
        The encoded JWT string.
    """
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "purpose": purpose,
        "exp": _expiry(timedelta(hours=expires_hours)),
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, secret_key, algorithm=algorithm)


def verify_signed_token_full(
    token: str,
    secret_key: str,
    expected_purpose: str,
    *,
    algorithm: str = DEFAULT_ALGORITHM,
) -> dict[str, Any] | None:
    """Verify a purpose-scoped signed token and return its full payload.

    Args:
        token: The encoded JWT.
        secret_key: HMAC key the token was signed with.
        expected_purpose: The ``purpose`` the token must carry.
        algorithm: JWT algorithm.

    Returns:
        The decoded claims (use when extra claims like ``new_email`` are needed),
        or ``None`` if invalid/expired or the purpose doesn't match.
    """
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
    except PyJWTError:
        return None
    if payload.get("purpose") != expected_purpose or payload.get("sub") is None:
        return None
    return payload


def verify_signed_token(
    token: str,
    secret_key: str,
    expected_purpose: str,
    *,
    algorithm: str = DEFAULT_ALGORITHM,
) -> str | None:
    """Verify a purpose-scoped signed token and return its subject.

    Args:
        token: The encoded JWT.
        secret_key: HMAC key the token was signed with.
        expected_purpose: The ``purpose`` the token must carry.
        algorithm: JWT algorithm.

    Returns:
        The ``sub`` (user id as a string), or ``None`` if invalid/expired or the
        purpose doesn't match.
    """
    payload = verify_signed_token_full(token, secret_key, expected_purpose, algorithm=algorithm)
    if payload is None:
        return None
    return str(payload["sub"])
