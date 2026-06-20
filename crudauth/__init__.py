"""crudauth - batteries-included, transport-agnostic authentication for FastAPI.

Quickstart:
    ```python
    from crudauth import CRUDAuth, Principal

    auth = CRUDAuth(session=get_session, user_model=User, SECRET_KEY="change-me")
    app.include_router(auth.router)

    @app.get("/me")
    async def me(user: Principal = Depends(auth.current_user())):
        return {"id": user.user_id}
    ```
"""

from __future__ import annotations

from importlib.metadata import version

from .core import AuthContext, CookieConfig, Transport
from .email import (
    DeliveryChannel,
    DeliveryIntent,
    DeliveryKind,
    EmailChannel,
    EmailConfig,
    EmailSender,
)
from .exceptions import (
    BadRequestException,
    CSRFException,
    DuplicateValueException,
    ForbiddenException,
    NotFoundException,
    RateLimitException,
    SudoLockoutError,
    UnauthorizedException,
    UnprocessableEntityException,
)
from .crud_auth import CRUDAuth
from .hooks import AuthHooks, HookContext
from .identity import IdentityConfig
from .models.mixin import AuthUserMixin, make_auth_identity
from .oauth import OAuthCredentials
from .principal import Principal
from .provisioning import NewUserContext, NewUserFields
from .sudo import SudoConfig
from .transports import BearerTransport, SessionTransport

__version__ = version("crudauth")

__all__ = [
    "__version__",
    "CRUDAuth",
    "Principal",
    "SessionTransport",
    "BearerTransport",
    "OAuthCredentials",
    "EmailConfig",
    "EmailSender",
    "DeliveryChannel",
    "DeliveryIntent",
    "DeliveryKind",
    "EmailChannel",
    "AuthHooks",
    "HookContext",
    "IdentityConfig",
    "AuthUserMixin",
    "make_auth_identity",
    "NewUserContext",
    "NewUserFields",
    "Transport",
    "AuthContext",
    "CookieConfig",
    "SudoConfig",
    # exceptions
    "BadRequestException",
    "NotFoundException",
    "ForbiddenException",
    "UnauthorizedException",
    "UnprocessableEntityException",
    "DuplicateValueException",
    "RateLimitException",
    "SudoLockoutError",
    "CSRFException",
]
