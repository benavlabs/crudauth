"""OAuth: providers, factory, account linking. ``crudauth[oauth]`` for httpx.

Importing this package registers the built-in providers (Google, GitHub) with
[OAuthProviderFactory][crudauth.oauth.factory.OAuthProviderFactory] as a side effect of importing ``.providers``.
"""

from __future__ import annotations

from . import providers as _providers  # noqa: F401  (registers built-in providers)
from .factory import OAuthProviderFactory
from .provider import AbstractOAuthProvider
from .providers import GenericOIDCProvider
from .schemas import OAuthCredentials, OAuthState, OAuthUserInfo
from .service import OAuthAccountService

__all__ = [
    "AbstractOAuthProvider",
    "GenericOIDCProvider",
    "OAuthProviderFactory",
    "OAuthCredentials",
    "OAuthUserInfo",
    "OAuthState",
    "OAuthAccountService",
]
