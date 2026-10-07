"""The ``CRUDAuth`` surface the route builders use, as a typed contract.

Router builders take the facade to reach the repository, hooks and the shared
dependencies, and importing [CRUDAuth][crudauth.crud_auth.CRUDAuth] for that
would be circular (it imports them). They take this Protocol instead, so what a
builder may touch is declared and type-checked.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable, Protocol

if TYPE_CHECKING:  # pragma: no cover
    from .core import AuthRuntime
    from .email.service import EmailFlowService
    from .hooks import AuthHooks
    from .identity import IdentityConfig
    from .password import PasswordPolicy, PasswordSource
    from .principal import Principal
    from .provisioning import NewUserFields
    from .ratelimit import KeyBy, RateLimit, RateLimitResolver, RateLimiterBackend
    from .repository import UserRepository

__all__ = ["AuthSurface"]


class AuthSurface(Protocol):
    """What a route builder may use on the configured [CRUDAuth][crudauth.crud_auth.CRUDAuth]."""

    session: Callable[..., Any]
    repo: UserRepository
    hooks: AuthHooks
    identity: IdentityConfig
    runtime: AuthRuntime
    password_policy: PasswordPolicy
    new_user_fields: NewUserFields | None
    new_user_defaults: dict[str, Any]

    @property
    def emails(self) -> EmailFlowService | None: ...

    @property
    def rate_limiter(self) -> RateLimiterBackend | None: ...

    @property
    def rate_limits(self) -> dict[str, RateLimit]: ...

    def current_user(
        self,
        *,
        optional: bool = False,
        superuser: bool = False,
        verified: bool = False,
        scopes: list[str] | None = None,
        transport: str | list[str] | None = None,
        check: Callable[..., Any] | None = None,
    ) -> Callable[..., Any]: ...

    def rate_limit(
        self,
        action: str,
        limit: RateLimit | RateLimitResolver | None = None,
        *,
        key: KeyBy | Callable[..., str] = ...,
        transport: str | list[str] | None = None,
    ) -> Callable[..., Any]: ...

    async def signed_in_recently(self, principal: Principal) -> bool: ...

    async def validate_password(
        self,
        password: str,
        *,
        user: Any = None,
        source: PasswordSource = "set",
        field: str = "password",
    ) -> None: ...
