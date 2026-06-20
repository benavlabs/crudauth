"""Builds the recovery-flow endpoints (verify / reset / change).

The trigger endpoints carry a per-IP rate-limit dependency (caller spray); the
service additionally enforces a silent per-target cap. The verify and reset
request bodies are shaped to the contract's recovery factor (``email`` validated
as an address, any other factor as a plain string), so a phone-recovery app can
drive them over HTTP with a phone number. Change-email is email-specific and only
mounts when the model actually has an email column.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, EmailStr, Field, create_model

from ..constants import MIN_PASSWORD_LENGTH
from ..principal import Principal
from ..ratelimit import KeyBy
from .service import EmailFlowService

__all__ = ["build_email_router"]


class _TokenIn(BaseModel):
    token: str


class _ResetIn(BaseModel):
    token: str
    new_password: Annotated[str, Field(min_length=MIN_PASSWORD_LENGTH)]


class _ChangeIn(BaseModel):
    new_email: EmailStr
    password: str


def build_email_router(*, auth: Any, service: EmailFlowService) -> APIRouter:
    """Build the recovery-flow router (verify / reset, plus change-email when applicable).

    The verify and reset request bodies are generated for the recovery factor: an
    email-recovery app keeps ``{"email": ...}`` (validated as an address), a
    phone-recovery app gets ``{"phone": ...}``. Change-email endpoints are added
    only when the model has an ``email`` column, since they prove a real address.

    Args:
        auth: The owning [CRUDAuth][crudauth.crud_auth.CRUDAuth] (for ``session``,
            ``current_user``, and ``rate_limit`` dependencies).
        service: The [EmailFlowService][crudauth.email.service.EmailFlowService] that mints/verifies tokens.

    Returns:
        An `APIRouter` with the recovery endpoints.
    """
    router = APIRouter(tags=["auth:email"])
    db_dep = auth.session
    user_dep = auth.current_user()

    factor = service.repo.recovery
    if factor is None:
        raise RuntimeError("the recovery router requires a recovery factor (identity.recovery)")
    field_type: Any = EmailStr if factor == "email" else str
    fields: dict[str, Any] = {factor: (field_type, ...)}
    RecoveryRequestModel = create_model("RecoveryRequestIn", **fields)
    channel_noun = "email" if factor == "email" else "message"

    @router.post(
        "/email/verify-request",
        dependencies=[Depends(auth.rate_limit("email_verify_request", key=KeyBy.IP))],
    )
    async def request_verification(
        body: RecoveryRequestModel,  # type: ignore[valid-type]
        db: Annotated[Any, Depends(db_dep)],
    ):
        """Send a verification link to the recovery factor. Always succeeds (no enumeration)."""
        await service.request_recovery_verification(db, getattr(body, factor))
        return {"detail": f"If an account exists, a verification {channel_noun} has been sent."}

    @router.post("/email/verify-confirm")
    async def confirm_verification(body: _TokenIn, db: Annotated[Any, Depends(db_dep)]):
        """Confirm a verification token and mark the recovery factor verified."""
        await service.confirm_recovery_verification(db, body.token)
        return {"detail": "Verified successfully."}

    @router.post(
        "/password/reset-request",
        dependencies=[Depends(auth.rate_limit("password_reset_request", key=KeyBy.IP))],
    )
    async def request_reset(
        body: RecoveryRequestModel,  # type: ignore[valid-type]
        db: Annotated[Any, Depends(db_dep)],
    ):
        """Send a password-reset link to the recovery factor. Always succeeds (no enumeration)."""
        await service.request_password_reset(db, getattr(body, factor))
        return {"detail": f"If an account exists, a password reset {channel_noun} has been sent."}

    @router.post("/password/reset-confirm")
    async def reset(body: _ResetIn, db: Annotated[Any, Depends(db_dep)]):
        """Reset the password from a valid token and evict the user's other sessions."""
        await service.reset_password(db, body.token, body.new_password)
        return {"detail": "Password reset successfully."}

    if service.repo.has("email"):

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
