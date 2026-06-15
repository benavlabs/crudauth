"""Builds the email-flow endpoints (verify / reset / change).

The three *trigger* endpoints carry a per-IP rate-limit dependency (caller
spray); the service additionally enforces a silent per-target-email cap.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, EmailStr, Field

from ..constants import MIN_PASSWORD_LENGTH
from ..principal import Principal
from ..ratelimit import KeyBy
from .service import EmailFlowService

__all__ = ["build_email_router"]


class _EmailIn(BaseModel):
    email: EmailStr


class _TokenIn(BaseModel):
    token: str


class _ResetIn(BaseModel):
    token: str
    new_password: Annotated[str, Field(min_length=MIN_PASSWORD_LENGTH)]


class _ChangeIn(BaseModel):
    new_email: EmailStr
    password: str


def build_email_router(*, auth: Any, service: EmailFlowService) -> APIRouter:
    """Build the email-flow router (verify / reset / change endpoints).

    Args:
        auth: The owning [CRUDAuth][crudauth.crud_auth.CRUDAuth] (for ``session``,
            ``current_user``, and ``rate_limit`` dependencies).
        service: The [EmailFlowService][crudauth.email.service.EmailFlowService] that mints/verifies tokens.

    Returns:
        An `APIRouter` with the six email endpoints.
    """
    router = APIRouter(tags=["auth:email"])
    db_dep = auth.session
    user_dep = auth.current_user()

    @router.post(
        "/email/verify-request",
        dependencies=[Depends(auth.rate_limit("email_verify_request", key=KeyBy.IP))],
    )
    async def request_verification(body: _EmailIn, db: Annotated[Any, Depends(db_dep)]):
        """Send an email-verification link. Always returns success (no enumeration)."""
        await service.request_email_verification(db, body.email)
        return {"detail": "If an account exists, a verification email has been sent."}

    @router.post("/email/verify-confirm")
    async def confirm_verification(body: _TokenIn, db: Annotated[Any, Depends(db_dep)]):
        """Confirm a verification token and mark the email verified."""
        await service.confirm_email_verification(db, body.token)
        return {"detail": "Email verified successfully."}

    @router.post(
        "/password/reset-request",
        dependencies=[Depends(auth.rate_limit("password_reset_request", key=KeyBy.IP))],
    )
    async def request_reset(body: _EmailIn, db: Annotated[Any, Depends(db_dep)]):
        """Send a password-reset link. Always returns success (no enumeration)."""
        await service.request_password_reset(db, body.email)
        return {"detail": "If an account exists, a password reset email has been sent."}

    @router.post("/password/reset-confirm")
    async def reset(body: _ResetIn, db: Annotated[Any, Depends(db_dep)]):
        """Reset the password from a valid token and evict the user's other sessions."""
        await service.reset_password(db, body.token, body.new_password)
        return {"detail": "Password reset successfully."}

    @router.post(
        "/email/change-request",
        dependencies=[Depends(auth.rate_limit("email_change_request", key=KeyBy.IP))],
    )
    async def change_request(
        body: _ChangeIn,
        db: Annotated[Any, Depends(db_dep)],
        principal: Annotated[Principal, Depends(user_dep)],
    ):
        """Request an email change (authenticated; re-auth via current password)."""
        await service.request_email_change(db, principal.user, body.new_email, body.password)
        return {"detail": "If the address is available, a confirmation email has been sent."}

    @router.post("/email/change-confirm")
    async def change_confirm(body: _TokenIn, db: Annotated[Any, Depends(db_dep)]):
        """Confirm an email-change token and apply the new address."""
        await service.confirm_email_change(db, body.token)
        return {"detail": "Email changed successfully."}

    return router
