"""Builds ``/me``, ``/set-password`` and ``/change-password``.

This module does NOT use ``from __future__ import annotations``: the password
bodies are created at runtime from the configured policy, and FastAPI must see
the real classes as annotations.
"""

from typing import TYPE_CHECKING, Annotated, Any, cast

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, create_model

from ..protocols import AuthSurface
from ..constants import FRESH_SIGN_IN_REQUIRED
from ..exceptions import BadRequestException, ForbiddenException, UnauthorizedException
from ..hooks import HookContext
from ..principal import Principal
from ..ratelimit import KeyBy
from ..utils import get_password_hash_async, is_unusable_password, verify_password_async

if TYPE_CHECKING:  # pragma: no cover
    from ..transports.session.manager import SessionManager

__all__ = ["build_account_router"]


class _SetPasswordIn(BaseModel):
    new_password: str


class _ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str


def build_account_router(auth: AuthSurface, session_manager: "SessionManager | None") -> APIRouter:
    """Build the account routes.

    Args:
        auth: The owning [CRUDAuth][crudauth.crud_auth.CRUDAuth].
        session_manager: The session transport's manager, or ``None`` without one;
            a password change revokes the account's other sessions through it.

    Returns:
        An `APIRouter` with ``GET /me``, ``POST /set-password`` and ``POST /change-password``.
    """
    router = APIRouter(tags=["auth"])
    repo = auth.repo
    user_dep = auth.current_user()
    password_field = (auth.password_policy.body_field(), ...)
    SetPasswordModel = create_model(
        "_SetPasswordIn", __base__=_SetPasswordIn, new_password=password_field
    )
    ChangePasswordModel = create_model(
        "_ChangePasswordIn", __base__=_ChangePasswordIn, new_password=password_field
    )

    @router.get("/me")
    async def me(user: Annotated[Principal, Depends(user_dep)]):
        """Return the authenticated user's identity, scopes, and auth transport."""
        return {
            "user_id": user.user_id,
            "username": repo.get(user.user, "username") if user.user else None,
            "email": repo.get(user.user, "email") if user.user else None,
            "is_superuser": user.is_superuser,
            "scopes": list(user.scopes),
            "via": user.transport,
        }

    @router.post("/set-password")
    async def set_password(
        body: SetPasswordModel,  # type: ignore[valid-type]
        principal: Annotated[Principal, Depends(user_dep)],
        db: Annotated[Any, Depends(auth.session)],
    ):
        """Set a password for an account that doesn't have one (OAuth-only).

        Note:
            There's no current password to re-enter, so the proof is a fresh
            sign-in: the session making the request must have signed in within
            ``fresh_sign_in_seconds`` (or hold sudo), else a 403 sends the person
            to sign in again. A password is a lasting credential, and with it email
            change and every other password-gated action, so an old or stolen
            session cookie must not be enough. A bearer token carries no sign-in
            time and is refused. This is **set**, not **change**: it refuses (400)
            if the account already has a usable password (use the password-reset
            flow to change an existing one). It does not evict other
            sessions/tokens (establishing a first credential isn't a compromise
            response).
        """
        user = principal.user
        new_password = cast(_SetPasswordIn, body).new_password
        if not is_unusable_password(repo.get(user, "hashed_password", "")):
            raise BadRequestException(
                "Account already has a password; use the password reset flow to change it."
            )
        if not await auth.signed_in_recently(principal):
            raise ForbiddenException(FRESH_SIGN_IN_REQUIRED)
        await auth.validate_password(new_password, user=user, source="set", field="new_password")
        await repo.update(
            db, user, {"hashed_password": await get_password_hash_async(new_password)}
        )
        return {"detail": "Password set."}

    @router.post(
        "/change-password",
        dependencies=[Depends(auth.rate_limit("change_password", key=KeyBy.USER))],
    )
    async def change_password(
        body: ChangePasswordModel,  # type: ignore[valid-type]
        request: Request,
        principal: Annotated[Principal, Depends(user_dep)],
        db: Annotated[Any, Depends(auth.session)],
    ):
        """Change the password for an authenticated account, verifying the current one.

        Note:
            Re-auth is the *current password*: the active session/token proves
            presence, the current password proves intent. Allowed over any
            transport - CSRF is automatic on the session path, and bearer has
            no CSRF surface. An account with no usable password gets a 400
            (use ``/set-password`` to create the first one).

        Note:
            A password change is a compromise response: it bumps
            ``token_version`` (evicting bearer tokens; a no-op without the
            column) and revokes the user's OTHER sessions, keeping the current
            one. Same eviction shape as a password reset.
        """
        user = principal.user
        current_hash = repo.get(user, "hashed_password", "")
        if is_unusable_password(current_hash):
            raise BadRequestException("Account has no password; use /set-password to create one.")
        change = cast(_ChangePasswordIn, body)
        if not await verify_password_async(change.current_password, current_hash):
            raise UnauthorizedException("Current password is incorrect.")
        await auth.validate_password(
            change.new_password, user=user, source="change", field="new_password"
        )
        await repo.update(
            db, user, {"hashed_password": await get_password_hash_async(change.new_password)}
        )
        await repo.increment_token_version(db, user)
        if session_manager is not None:
            current_sid = principal.metadata.get("session_id")
            if current_sid:
                await session_manager.set_token_version(current_sid, repo.token_version(user))
            await session_manager.revoke_all(principal.user_id, exclude=current_sid)
        await auth.hooks.run_after_password_changed(
            repo.to_dict(user),
            db=db,
            context=HookContext(transport=principal.transport, request=request),
        )
        return {"detail": "Password changed."}

    return router
