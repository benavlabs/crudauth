"""Unit tests for password hashing, verification, and the unusable sentinel."""

from __future__ import annotations

from crudauth.utils import (
    dummy_verify_password,
    get_password_hash,
    make_unusable_password,
    verify_password,
)


def test_password_roundtrip() -> None:
    h = get_password_hash("hunter2")
    assert verify_password("hunter2", h)
    assert not verify_password("wrong", h)


def test_verify_password_handles_malformed_hash() -> None:
    assert verify_password("anything", "not-a-bcrypt-hash") is False


def test_unusable_password_never_verifies() -> None:
    sentinel = make_unusable_password()
    assert not verify_password("", sentinel)
    assert not verify_password("password", sentinel)


def test_long_password_not_truncated_at_72_bytes() -> None:
    # Two passwords sharing a 72-byte prefix must NOT be interchangeable
    # (bcrypt alone truncates at 72 bytes; the SHA-256 pre-hash prevents it).
    base = "a" * 72
    h = get_password_hash(base + "X")
    assert verify_password(base + "X", h)
    assert not verify_password(base + "Y", h)
    assert not verify_password(base, h)


def test_password_roundtrip_very_long() -> None:
    pw = "correct horse battery staple " * 10
    assert verify_password(pw, get_password_hash(pw))


def test_dummy_verify_password_runs_without_raising() -> None:
    # Exercises the absent-user timing-equalization path; must not raise.
    dummy_verify_password("whatever")
