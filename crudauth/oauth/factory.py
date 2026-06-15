"""Registry mapping provider names to [AbstractOAuthProvider][crudauth.oauth.provider.AbstractOAuthProvider] subclasses."""

from __future__ import annotations

from typing import Any

from .provider import AbstractOAuthProvider

__all__ = ["OAuthProviderFactory"]


class OAuthProviderFactory:
    """Process-wide registry of provider name -> provider class.

    Built-in providers (``"google"``, ``"github"``) register themselves when
    [crudauth.oauth][crudauth.oauth] is imported; register your own with
    [register_provider][crudauth.oauth.factory.OAuthProviderFactory.register_provider].

    Example:
        ```python
        OAuthProviderFactory.register_provider("gitlab", GitLabOAuthProvider)
        ```
    """

    _providers: dict[str, type[AbstractOAuthProvider]] = {}

    @classmethod
    def register_provider(
        cls, provider_name: str, provider_class: type[AbstractOAuthProvider]
    ) -> None:
        """Register ``provider_class`` under ``provider_name`` (overwrites any existing)."""
        cls._providers[provider_name] = provider_class

    @classmethod
    def get_provider_class(cls, provider_name: str) -> type[AbstractOAuthProvider] | None:
        """Return the registered class for ``provider_name``, or ``None``."""
        return cls._providers.get(provider_name)

    @classmethod
    def create_provider(
        cls,
        provider_name: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: list[str] | None = None,
    ) -> AbstractOAuthProvider:
        """Instantiate a registered provider.

        Args:
            provider_name: A registered provider name.
            client_id: OAuth client id.
            client_secret: OAuth client secret.
            redirect_uri: The callback URI registered with the provider.
            scopes: Override the provider's default scopes.

        Returns:
            A configured [AbstractOAuthProvider][crudauth.oauth.provider.AbstractOAuthProvider].

        Raises:
            ValueError: If ``provider_name`` isn't registered. This is a
                config-time error (raised while building the app), distinct from
                the request-time ``BadRequestException`` the OAuth router raises
                for an unknown provider in a URL - different layers, deliberately
                different error types.
        """
        provider_class = cls._providers.get(provider_name)
        if provider_class is None:
            raise ValueError(f"Unknown OAuth provider: {provider_name!r}")
        kwargs: dict[str, Any] = {}
        if scopes is not None:
            kwargs["scopes"] = scopes
        return provider_class(client_id, client_secret, redirect_uri, **kwargs)
