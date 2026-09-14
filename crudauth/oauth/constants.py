"""Constants for the OAuth flows."""

from __future__ import annotations

# Built-in provider names.
GOOGLE = "google"
GITHUB = "github"

# OAuth-generated-username shaping.
USERNAME_MIN_LENGTH = 2
USERNAME_MAX_LENGTH = 32
USERNAME_FALLBACK = "user"
# Numbered-suffix attempts before giving up and using a random suffix.
USERNAME_MAX_SUFFIX_ATTEMPTS = 100
USERNAME_RANDOM_SUFFIX_BYTES = 4

# PKCE / state entropy (bytes passed to secrets.token_urlsafe).
STATE_BYTES = 32
PKCE_VERIFIER_BYTES = 64

# Short-lived cookie that binds the OAuth state to the browser that began the
# flow, so a callback URL captured by an attacker can't log a victim in.
OAUTH_STATE_COOKIE_NAME = "oauth_state"

# Network timeout (seconds) for OAuth token-exchange / userinfo HTTP calls, so a
# hung provider can't stall a request indefinitely.
OAUTH_HTTP_TIMEOUT_SECONDS = 10

# Google endpoints + default scopes.
GOOGLE_AUTHORIZE_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v3/userinfo"
GOOGLE_DEFAULT_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]

# GitHub endpoints + default scopes.
GITHUB_AUTHORIZE_ENDPOINT = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_ENDPOINT = "https://github.com/login/oauth/access_token"
GITHUB_USERINFO_ENDPOINT = "https://api.github.com/user"
GITHUB_EMAILS_ENDPOINT = "https://api.github.com/user/emails"
GITHUB_DEFAULT_SCOPES = ["read:user", "user:email"]

# Generic OIDC: discovery path + the minimal scopes for an id/userinfo lookup.
OIDC_DISCOVERY_PATH = "/.well-known/openid-configuration"
OIDC_DEFAULT_SCOPES = ["openid", "profile", "email"]
