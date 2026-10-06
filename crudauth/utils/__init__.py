"""Cross-cutting helpers: password hashing, email normalization, request IP."""

from __future__ import annotations

from .callbacks import takes_two_arguments
from .hashing import (
    LegacyVerifier,
    dummy_verify_password,
    get_password_hash,
    get_password_hash_async,
    is_unusable_password,
    make_unusable_password,
    normalize_password,
    verify_and_update_password,
    verify_and_update_password_async,
    verify_legacy_password,
    verify_legacy_password_async,
    verify_password,
    verify_password_async,
    verify_plain_bcrypt,
)
from .http import client_ip_key, get_client_ip, is_cross_site, safe_redirect_path
from .identifiers import canonical_email, canonical_identifier, mask_email

__all__ = [
    "normalize_password",
    "get_password_hash",
    "get_password_hash_async",
    "verify_password",
    "verify_password_async",
    "verify_and_update_password",
    "verify_and_update_password_async",
    "dummy_verify_password",
    "LegacyVerifier",
    "verify_plain_bcrypt",
    "verify_legacy_password",
    "verify_legacy_password_async",
    "make_unusable_password",
    "is_unusable_password",
    "canonical_email",
    "canonical_identifier",
    "mask_email",
    "get_client_ip",
    "is_cross_site",
    "client_ip_key",
    "safe_redirect_path",
    "takes_two_arguments",
]
