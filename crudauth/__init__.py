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

from .constants import REGISTRATION_ALLOWED_FIELDS, REGISTRATION_GATED_FIELDS
from .core import AuthContext, CookieConfig, Transport
from .email import (
    DeliveryChannel,
    DeliveryIntent,
    DeliveryKind,
    EmailChannel,
    EmailConfig,
    EmailContext,
    EmailSender,
)
from .exceptions import (
    BadRequestException,
    CSRFException,
    DuplicateValueException,
    ForbiddenException,
    NotFoundException,
    OAuthAccountException,
    PasswordPolicyException,
    RateLimitException,
    SudoLockoutError,
    UnauthorizedException,
    UnprocessableEntityException,
    ValueTooLongException,
)
from .crud_auth import CRUDAuth
from .email.service import EmailFlowResult, EmailFlowService
from .hooks import AuthHooks, HookContext
from .identity import IdentityConfig
from .mfa import MfaConfig, MfaService
from .models.mixin import AuthUserMixin, make_auth_identity
from .oauth import OAuthAccountService, OAuthCredentials
from .principal import Principal
from .password import PasswordContext, PasswordPolicy
from .provisioning import NewUserContext, NewUserFields
from .repository import UserRepository
from .sudo import SudoConfig, SudoManager
from .transports import BearerTransport, SessionTransport
from .transports.session.management import SessionInfo
from .transports.session.manager import SessionManager
from .utils import (
    get_password_hash,
    get_password_hash_async,
    is_unusable_password,
    make_unusable_password,
    safe_redirect_path,
    verify_password,
    verify_password_async,
)

__version__ = version("crudauth")

__all__ = [
    "__version__",
    "CRUDAuth",
    "REGISTRATION_ALLOWED_FIELDS",
    "REGISTRATION_GATED_FIELDS",
    "SessionInfo",
    "Principal",
    "SessionTransport",
    "BearerTransport",
    "OAuthCredentials",
    "EmailConfig",
    "EmailFlowResult",
    "EmailSender",
    "EmailContext",
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
    "PasswordPolicy",
    "PasswordContext",
    "SudoConfig",
    "MfaConfig",
    # toolbox: reusable building blocks (use the wired services off `auth`, or
    # construct/type them directly). Token issuance is intentionally not exported
    # here - use `auth.issue_tokens(...)` so the scope clamp and epoch come along.
    "UserRepository",
    "SessionManager",
    "SudoManager",
    "MfaService",
    "EmailFlowService",
    "OAuthAccountService",
    "get_password_hash",
    "get_password_hash_async",
    "verify_password",
    "verify_password_async",
    "is_unusable_password",
    "make_unusable_password",
    "safe_redirect_path",
    # exceptions
    "BadRequestException",
    "NotFoundException",
    "OAuthAccountException",
    "ForbiddenException",
    "UnauthorizedException",
    "UnprocessableEntityException",
    "DuplicateValueException",
    "ValueTooLongException",
    "PasswordPolicyException",
    "RateLimitException",
    "SudoLockoutError",
    "CSRFException",
]
