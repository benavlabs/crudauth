"""Where the OAuth routes live, and the callback URL providers redirect to."""

from __future__ import annotations

from urllib.parse import urlsplit

from ..utils import safe_redirect_path

__all__ = ["DEFAULT_OAUTH_PATHS", "resolve_oauth_paths", "callback_url", "is_redirect_target"]

DEFAULT_OAUTH_PATHS = {
    "prefix": "/oauth",
    "authorize_path": "/{provider}/authorize",
    "callback_path": "/{provider}/callback",
}


def resolve_oauth_paths(overrides: dict[str, str] | None) -> dict[str, str]:
    """The defaults with ``overrides`` applied.

    Raises:
        ValueError: If ``overrides`` has a key that isn't a known path.
    """
    unknown = sorted(set(overrides or {}) - set(DEFAULT_OAUTH_PATHS))
    if unknown:
        raise ValueError(
            f"Unknown oauth_paths key(s) {unknown}; expected {sorted(DEFAULT_OAUTH_PATHS)}."
        )
    return {**DEFAULT_OAUTH_PATHS, **(overrides or {})}


def callback_url(base_url: str, paths: dict[str, str], provider: str) -> str:
    """The absolute callback URL registered with ``provider``."""
    callback = paths["callback_path"].replace("{provider}", provider)
    route = "/".join(part.strip("/") for part in (paths["prefix"], callback) if part.strip("/"))
    return f"{base_url.rstrip('/')}/{route}"


def is_redirect_target(target: str) -> bool:
    """Whether ``target`` is a same-origin path or an absolute ``http(s)`` URL."""
    if safe_redirect_path(target, default="") == target:
        return True
    parts = urlsplit(target)
    return parts.scheme in ("http", "https") and bool(parts.netloc)
