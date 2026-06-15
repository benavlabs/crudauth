"""Unit tests for email/identifier canonicalization and the display mask."""

from __future__ import annotations

from crudauth.utils import canonical_email, canonical_identifier, mask_email


def test_canonical_email() -> None:
    assert canonical_email("  Foo@X.com ") == "foo@x.com"
    assert canonical_email(None) is None


def test_mask_email() -> None:
    assert mask_email("john@example.com") == "j***@example.com"
    assert mask_email("ab@x.io") == "a***@x.io"
    assert mask_email("a@x.io") == "a***@x.io"  # single-char local doesn't leak more
    assert mask_email("not-an-email") == "***"
    assert mask_email("") == "***"


# --- login identifier canonicalization (lockout key) -------------------------
def test_canonical_identifier_normalizes_email_case() -> None:
    assert canonical_identifier("V@X.com") == "v@x.com"
    assert canonical_identifier("  Foo@x.com ") == "foo@x.com"


def test_canonical_identifier_leaves_usernames_untouched() -> None:
    assert canonical_identifier("Alice") == "Alice"
