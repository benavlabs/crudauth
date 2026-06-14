"""Constants for the session transport."""

from __future__ import annotations

# HTTP methods that don't mutate state and are therefore exempt from CSRF.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

# Default cookie names.
SESSION_COOKIE_NAME = "session_id"
CSRF_COOKIE_NAME = "csrf_token"

# Header the SPA echoes the CSRF token in (the synchronizer-token check).
CSRF_HEADER_NAME = "X-CSRF-Token"

# Storage key prefixes for the session and CSRF stores.
SESSION_STORAGE_PREFIX = "session:"
CSRF_STORAGE_PREFIX = "csrf:"

# Session-metadata keys.
REMEMBER_ME_META_KEY = "remember_me"
CSRF_TOKEN_ID_META_KEY = "csrf_token_id"
# Absolute (ISO-8601) instant a sudo elevation expires; absent/past means not
# elevated. Stored on the session so it dies with the session (logout clears it).
SUDO_ELEVATED_UNTIL_META_KEY = "sudo_elevated_until"
