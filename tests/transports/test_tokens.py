"""Unit tests for bearer JWT tokens: create/verify, type/secret/expiry, signed tokens."""

from __future__ import annotations

from datetime import timedelta

from crudauth.transports.bearer.tokens import (
    TokenType,
    create_access_token,
    create_signed_token,
    is_expired_token,
    verify_signed_token,
    verify_token,
)

SECRET = "test-secret-key-0123456789-0123456789"


def test_access_token_roundtrip() -> None:
    token = create_access_token({"sub": "42"}, SECRET, scopes=["a", "b"])
    payload = verify_token(token, SECRET, TokenType.ACCESS)
    assert payload is not None
    assert payload["sub"] == "42"
    assert payload["scopes"] == ["a", "b"]


def test_access_token_wrong_type_rejected() -> None:
    token = create_access_token({"sub": "42"}, SECRET)
    assert verify_token(token, SECRET, TokenType.REFRESH) is None


def test_token_wrong_secret_rejected() -> None:
    token = create_access_token({"sub": "42"}, SECRET)
    assert verify_token(token, "wrong-secret-key-0123456789-0123456789", TokenType.ACCESS) is None


def test_expired_token_rejected() -> None:
    token = create_access_token({"sub": "42"}, SECRET, expires_delta=timedelta(seconds=-1))
    assert verify_token(token, SECRET, TokenType.ACCESS) is None


def test_is_expired_token_distinguishes_expiry_from_tampering() -> None:
    valid = create_access_token({"sub": "1"}, SECRET)
    expired = create_access_token({"sub": "1"}, SECRET, expires_delta=timedelta(seconds=-1))
    assert is_expired_token(valid, SECRET) is False
    assert is_expired_token(expired, SECRET) is True
    assert is_expired_token("garbage", SECRET) is False
    # expired AND wrong signature reads as tampered (signature checked first), not "just expired"
    assert is_expired_token(expired, "wrong-secret-key-0123456789-0123456789") is False


def test_signed_token_purpose() -> None:
    token = create_signed_token(SECRET, 7, "verify_email")
    assert verify_signed_token(token, SECRET, "verify_email") == "7"
    assert verify_signed_token(token, SECRET, "reset_password") is None
