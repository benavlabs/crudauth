"""Constants for the bearer transport."""

from __future__ import annotations

# The ``token_type`` value in token responses and the ``Authorization`` scheme.
TOKEN_TYPE_BEARER = "bearer"

# Where the refresh token is delivered.
REFRESH_LOCATION_COOKIE = "cookie"
REFRESH_LOCATION_BODY = "body"
REFRESH_LOCATIONS = frozenset({REFRESH_LOCATION_COOKIE, REFRESH_LOCATION_BODY})

# Default refresh-token cookie name and the JSON key it falls back to.
REFRESH_TOKEN_NAME = "refresh_token"

# JWT claim carrying the user's credential epoch (see AuthUserMixin.token_version);
# a token whose value is below the stored version is treated as revoked.
TOKEN_VERSION_CLAIM = "ver"
