"""Builds the ``/mfa`` endpoints: challenge verification, enrollment, recovery codes."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel

from ..protocols import AuthSurface
from ..constants import FRESH_SIGN_IN_REQUIRED
from ..exceptions import ForbiddenException, UnauthorizedException
from ..hooks import HookContext
from ..principal import Principal
from ..ratelimit import KeyBy
from ..utils import get_client_ip, is_unusable_password, verify_password_async
from .service import MfaService

__all__ = ["build_mfa_router"]


class _VerifyIn(BaseModel):
    challenge: str
    code: str


class _ChallengeIn(BaseModel):
    challenge: str


class _SetupIn(BaseModel):
    password: str | None = None


class _CodeIn(BaseModel):
    code: str


def build_mfa_router(*, auth: AuthSurface, service: MfaService) -> APIRouter:
    """Build the MFA router.

    ``/mfa/verify`` and ``/mfa/challenge`` answer a login challenge and need no
    credential. The rest act on the signed-in account and share the ``mfa_manage``
    rate limit per user.

    Args:
        auth: The owning [CRUDAuth][crudauth.crud_auth.CRUDAuth].
        service: The [MfaService][crudauth.mfa.service.MfaService].

    Returns:
        An `APIRouter` with the MFA endpoints.
    """
    router = APIRouter(prefix="/mfa", tags=["auth:mfa"])
    db_dep = auth.session
    user_dep = auth.current_user()
    manage_limit = [Depends(auth.rate_limit("mfa_manage", key=KeyBy.USER))]

    def _context(request: Request, principal: Principal) -> HookContext:
        return HookContext(
            ip_address=get_client_ip(request, auth.runtime.trusted_proxy_hops),
            user_agent=request.headers.get("user-agent"),
            transport=principal.transport,
            request=request,
        )

    @router.post("/verify")
    async def verify(
        body: _VerifyIn,
        request: Request,
        response: Response,
        db: Annotated[Any, Depends(db_dep)],
    ):
        """Answer a login challenge with an authenticator or recovery code and finish the login."""
        return await service.complete_challenge(
            db, body.challenge, body.code, request=request, response=response
        )

    @router.post("/challenge")
    async def challenge(body: _ChallengeIn, db: Annotated[Any, Depends(db_dep)]):
        """Return the enrollment details (``setup``) of a live challenge, or ``null``."""
        return await service.describe_challenge(db, body.challenge)

    @router.get("")
    async def status(principal: Annotated[Principal, Depends(user_dep)]):
        """Whether MFA is enabled and required for the account, and recovery codes left."""
        return await service.status(principal.user)

    @router.post("/totp/setup", dependencies=manage_limit)
    async def setup(
        body: _SetupIn,
        principal: Annotated[Principal, Depends(user_dep)],
        db: Annotated[Any, Depends(db_dep)],
    ):
        """Start enrollment: returns a new ``secret`` and its ``otpauth_uri``.

        An account with a password must send it, so a stolen session can't enroll an
        authenticator the owner doesn't have. An account without one (OAuth-only) must
        have signed in within ``fresh_sign_in_seconds`` on this session, or hold sudo;
        otherwise it gets a 403 and signs in again.
        """
        user = principal.user
        hashed_password = auth.repo.get(user, "hashed_password")
        if is_unusable_password(hashed_password):
            if not await auth.signed_in_recently(principal):
                raise ForbiddenException(FRESH_SIGN_IN_REQUIRED)
        elif body.password is None or not await verify_password_async(
            body.password, hashed_password
        ):
            raise UnauthorizedException("Incorrect password")
        return await service.begin_setup(db, user)

    @router.post("/totp/confirm", dependencies=manage_limit)
    async def confirm(
        body: _CodeIn,
        request: Request,
        principal: Annotated[Principal, Depends(user_dep)],
        db: Annotated[Any, Depends(db_dep)],
    ):
        """Confirm enrollment with a code; returns the ``recovery_codes``, shown once."""
        codes = await service.confirm_setup(
            db, principal.user, body.code, context=_context(request, principal)
        )
        return {"recovery_codes": codes}

    @router.post("/totp/disable", dependencies=manage_limit)
    async def disable(
        body: _CodeIn,
        request: Request,
        principal: Annotated[Principal, Depends(user_dep)],
        db: Annotated[Any, Depends(db_dep)],
    ):
        """Turn MFA off with a current authenticator or recovery code (403 when required)."""
        user = principal.user
        context = _context(request, principal)
        if await service.is_required(user):
            raise ForbiddenException("Two-factor authentication is required for this account.")
        if not await service.verify_code(db, user, body.code, context=context):
            raise UnauthorizedException("Invalid code")
        await service.disable(db, user, context=context)
        return {"detail": "Two-factor authentication disabled."}

    @router.post("/recovery-codes/regenerate", dependencies=manage_limit)
    async def regenerate(
        body: _CodeIn,
        request: Request,
        principal: Annotated[Principal, Depends(user_dep)],
        db: Annotated[Any, Depends(db_dep)],
    ):
        """Replace the recovery codes, given a current authenticator or recovery code."""
        user = principal.user
        if not await service.verify_code(db, user, body.code, context=_context(request, principal)):
            raise UnauthorizedException("Invalid code")
        return {"recovery_codes": await service.regenerate_recovery_codes(db, user)}

    return router
