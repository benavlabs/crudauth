"""The ``/register`` route, factored out so a custom request schema works.

This module deliberately does NOT use ``from __future__ import annotations``:
the request model is chosen at runtime (``register_schema=``), and FastAPI must
see the real Pydantic class as the body annotation, not a deferred string.
"""

import logging
from collections.abc import Awaitable
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.exc import IntegrityError

from ..constants import MIN_PASSWORD_LENGTH
from ..exceptions import DuplicateValueException
from ..hooks import HookContext
from ..provisioning import NewUserContext, resolve_new_user_fields
from ..ratelimit import KeyBy
from ..utils import get_client_ip, get_password_hash

__all__ = ["RegisterIn", "build_register_route"]

logger = logging.getLogger("crudauth")

_ENROLLED_DETAIL = "If the email is available, check your inbox to finish signing up."


class RegisterIn(BaseModel):
    """Default registration body. Supply your own via ``register_schema=`` to add
    fields - but an extra field is persisted only if its name is opted in via
    ``register_extra_fields=``; otherwise registration drops it.

    Note:
        ``password`` enforces ``MIN_PASSWORD_LENGTH`` (matching the reset flow). A
        custom ``register_schema`` governs its own policy - apply your own
        ``Field`` constraints / validators there.
    """

    email: EmailStr
    username: str
    password: Annotated[str, Field(min_length=MIN_PASSWORD_LENGTH)]


def build_register_route(auth: Any, schema: type[BaseModel] | None) -> APIRouter:
    """Build the ``/register`` router using ``schema`` (or the default body).

    Args:
        auth: The owning [CRUDAuth][crudauth.crud_auth.CRUDAuth] (repo, hooks, rate limit, ...).
        schema: Custom request body, or ``None`` to use [RegisterIn][crudauth.register.route.RegisterIn].

    Returns:
        An `APIRouter` with the ``POST /register`` route.
    """
    router = APIRouter(tags=["auth"])
    RegisterModel = schema or RegisterIn

    @router.post("/register", dependencies=[Depends(auth.rate_limit("register", key=KeyBy.IP))])
    async def register(
        body: RegisterModel,  # type: ignore[valid-type]
        request: Request,
        response: Response,
        db: Annotated[Any, Depends(auth.session)],
    ):
        """Register a user.

        Note:
            ``password`` is plaintext input (never a column) and is pulled out
            before gating, then hashed. [UserRepository.filter_registration_data][crudauth.repository.UserRepository.filter_registration_data]
            then keeps only the allowlisted fields (``email``/``username`` plus
            any names opted in via ``register_extra_fields``) - the security
            boundary that stops a (mis)declared ``register_schema`` from setting
            privileged state or unknown app columns. Privileged fields
            (``is_superuser``, ``email_verified``, ``hashed_password``, oauth
            linkage, ``id``) are dropped unconditionally; app columns like
            ``full_name`` are dropped unless opted in.

        Note:
            When email is configured, a brand-new and an already-registered email
            return the SAME ``202`` + body (the new user gets a verification mail,
            the owner of an existing address gets a notice) so the response can't
            confirm whether an account exists. With no email
            channel, dev mode surfaces the duplicate instead - there's no way to
            both not-leak and tell a genuine new user. A username collision is
            always allowed to surface (public namespace).
        """
        ip = get_client_ip(request, auth.runtime.trusted_proxy_hops)
        email_on = auth._email_service is not None
        data = cast(BaseModel, body).model_dump()
        password = data.pop("password")
        submitted = dict(data)
        data = auth.repo.filter_registration_data(data)
        email = data.pop("email")
        username = data.pop("username")

        async def _send_best_effort(coro: Awaitable[Any]) -> None:
            """Dispatch a registration email without letting a send failure fail
            the request.

            The account row may already be committed, and the new-vs-existing
            email branches must return the same status; a raised send (SMTP down)
            would both lose the registration to a 500 and turn the failure into an
            enumeration oracle. So failures are logged and swallowed. Senders
            should enqueue rather than block (see
            [EmailSender.send][crudauth.email.sender.EmailSender.send]).
            """
            try:
                await coro
            except Exception:
                logger.warning("crudauth: registration email failed to send", exc_info=True)

        async def _on_existing() -> dict[str, Any]:
            """Uniform response when the email/username is already taken.

            Shared by the read-time pre-check and the ``IntegrityError``
            race-recovery so a concurrent duplicate yields the same clean result
            (202 when email is configured, else a duplicate error) instead of a
            500, and non-enumeration is preserved.
            """
            if await auth.repo.get_by_email(db, email) is not None:
                if email_on:
                    await _send_best_effort(auth._email_service.notify_existing_account(email))
                    response.status_code = status.HTTP_202_ACCEPTED
                    return {"detail": _ENROLLED_DETAIL}
                raise DuplicateValueException("Email already registered")
            raise DuplicateValueException("Username already taken")

        if await auth.repo.get_by_email(db, email) is not None or await auth.repo.username_exists(
            db, username
        ):
            return await _on_existing()

        create_data: dict[str, Any] = {
            "email": email,
            "username": username,
            "hashed_password": get_password_hash(password),
        }
        create_data.update(data)
        create_data.update(auth._new_user_defaults)
        create_data.update(
            await resolve_new_user_fields(
                auth.new_user_fields,
                NewUserContext(
                    email=email,
                    username=username,
                    source="register",
                    db=db,
                    register_data=submitted,
                    oauth=None,
                ),
                auth.repo,
            )
        )

        try:
            user = await auth.repo.create(db, create_data)
        except IntegrityError:
            await db.rollback()
            return await _on_existing()
        await auth.hooks.run_after_register(
            auth.repo.to_dict(user),
            db=db,
            context=HookContext(
                ip_address=ip,
                user_agent=request.headers.get("user-agent"),
                request=request,
            ),
        )

        if email_on:
            await _send_best_effort(auth._email_service.request_email_verification(db, email))
            response.status_code = status.HTTP_202_ACCEPTED
            return {"detail": _ENROLLED_DETAIL}
        return {
            "id": auth.repo.user_id(user),
            "email": auth.repo.get(user, "email"),
            "username": auth.repo.get(user, "username"),
        }

    return router
