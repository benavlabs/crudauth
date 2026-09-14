"""Built-in OAuth providers (Google, GitHub), registered on import."""

from __future__ import annotations

from ..constants import GITHUB, GOOGLE
from ..factory import OAuthProviderFactory
from .github import GitHubOAuthProvider
from .google import GoogleOAuthProvider
from .oidc import GenericOIDCProvider

OAuthProviderFactory.register_provider(GOOGLE, GoogleOAuthProvider)
OAuthProviderFactory.register_provider(GITHUB, GitHubOAuthProvider)

# GenericOIDCProvider is intentionally NOT registered: the factory's
# create_provider builds from name + credentials alone, but an OIDC provider
# needs its endpoints resolved from an issuer first. Construct it with
# GenericOIDCProvider.from_discovery(...) instead.

__all__ = ["GoogleOAuthProvider", "GitHubOAuthProvider", "GenericOIDCProvider"]
