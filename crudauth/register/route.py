"""The ``/register`` route, factored out so a custom request schema works.

This module deliberately does NOT use ``from __future__ import annotations``:
the request model is chosen at runtime (``register_schema=``), and FastAPI must
see the real Pydantic class as the body annotation, not a deferred string.
"""

import logging
from collections.abc import Awaitable
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, Request, Response, status
from pydantic import BaseModel, EmailStr, create_model
from sqlalchemy.exc import IntegrityError

from ..protocols import AuthSurface
from ..exceptions import DuplicateValueException, ValueTooLongException
from ..hooks import HookContext
from ..password import PasswordContext
from ..provisioning import NewUserContext, resolve_new_user_fields
from ..ratelimit.dependency import enforce_rate_limit
from ..utils import client_ip_key, get_client_ip, get_password_hash_async

__all__ = ["RegisterIn", "build_register_route"]

logger = logging.getLogger("crudauth")

_ENROLLED_DETAIL = "If the email is available, check your inbox to finish signing up."


class RegisterIn(BaseModel):
    """Default registration body. Supply your own via ``register_schema=`` to add
    fields - but an extra field is persisted only if its name is opted in via
    ``register_extra_fields=``; otherwise registration drops it.

    Note:
        ``password`` must meet the configured
        [PasswordPolicy][crudauth.password.PasswordPolicy], which runs on a custom
        ``register_schema`` too.
    """

    email: EmailStr
    username: str
    password: str


def build_register_route(auth: AuthSurface, schema: type[BaseModel] | None) -> APIRouter:
    """Build the ``/register`` router using ``schema`` (or the default body).

    Args:
        auth: The owning [CRUDAuth][crudauth.crud_auth.CRUDAuth] (repo, hooks, rate limit, ...).
        schema: Custom request body, or ``None`` to use [RegisterIn][crudauth.register.route.RegisterIn].

    Returns:
        An `APIRouter` with the ``POST /register`` route.
    """
    router = APIRouter(tags=["auth"])
    RegisterModel = schema or create_model(
        "RegisterIn", __base__=RegisterIn, password=(auth.password_policy.body_field(), ...)
    )

    @router.post("/register")
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
            or recovery value return the SAME ``202`` + body (the new user gets a
            verification message, the owner of the existing value gets a notice),
            and so does any other unique-constraint collision, so the response
            can't confirm whether an account exists. Both paths hash the password
            once, so timing doesn't tell them apart either. With no email
            channel, dev mode surfaces the duplicate instead - there's no way to
            both not-leak and tell a genuine new user. A username collision is
            always allowed to surface (public namespace).

        Note:
            The ``register`` rate limit counts only requests that pass validation
            (the body schema, the password policy, and column lengths), so a user
            retrying a rejected password isn't locked out of signing up.
        """
        ip = get_client_ip(request, auth.runtime.trusted_proxy_hops)
        emails = auth.emails
        email_on = emails is not None
        login_fields = auth.identity.login
        data = cast(BaseModel, body).model_dump()
        password = data.pop("password")
        await auth.password_policy.enforce(
            password,
            PasswordContext(
                source="register", username=data.get("username"), email=data.get("email")
            ),
        )
        submitted = dict(data)
        data = auth.repo.filter_registration_data(data)
        login_values = {f: data.pop(f) for f in login_fields}
        too_long = {
            field: limit
            for field, value in {**login_values, **data}.items()
            if (limit := auth.repo.exceeds_length(field, value)) is not None
        }
        if too_long:
            raise ValueTooLongException(too_long)
        await enforce_rate_limit(
            auth.rate_limiter,
            request,
            response,
            action="register",
            identity=client_ip_key(ip),
            limit=auth.rate_limits["register"],
        )
        hashed_password = await get_password_hash_async(password)
        unique_values = {
            field: value
            for field, value in {**login_values, **data}.items()
            if value is not None and auth.repo.is_unique_column(field)
        }
        private_fields = {"email", auth.identity.recovery}

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

        def _enrolled() -> dict[str, Any]:
            response.status_code = status.HTTP_202_ACCEPTED
            return {"detail": _ENROLLED_DETAIL}

        async def _on_existing() -> dict[str, Any]:
            """Uniform response when a submitted unique value is already taken.

            Shared by the read-time pre-check and the ``IntegrityError``
            race-recovery so a concurrent duplicate yields the same clean result
            (202 when email is configured, else a duplicate error) instead of a
            500, and non-enumeration is preserved. The email and the recovery
            value notify their owner; a login field such as ``username`` always
            surfaces (public namespace); any other unique column is ``202`` too
            when email is configured.

            Note:
                The trailing "Account already exists" raise is reached only if a
                collision the caller detected has since vanished (the colliding row
                was deleted between detection and this re-query) - a rare race, not
                dead code.
            """
            for field, value in unique_values.items():
                if await auth.repo.get_by_field(db, field, value) is None:
                    continue
                if field in private_fields:
                    if emails is not None:
                        await _send_best_effort(emails.notify_existing_account(value))
                        return _enrolled()
                    raise DuplicateValueException(f"{field.capitalize()} already registered")
                if email_on and field not in login_fields:
                    return _enrolled()
                raise DuplicateValueException(f"{field.capitalize()} already taken")
            raise DuplicateValueException("Account already exists")

        for field, value in unique_values.items():
            if await auth.repo.get_by_field(db, field, value) is not None:
                return await _on_existing()

        create_data: dict[str, Any] = {**login_values, "hashed_password": hashed_password}
        create_data.update(data)
        create_data.update(auth.new_user_defaults)
        create_data.update(
            await resolve_new_user_fields(
                auth.new_user_fields,
                NewUserContext(
                    email=login_values.get("email", ""),
                    username=login_values.get("username", ""),
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
        await auth.repo.refresh_if_expired(db, user)

        if emails is not None and auth.identity.recovery is not None:
            await _send_best_effort(
                emails.request_recovery_verification(
                    db, auth.repo.get(user, auth.identity.recovery)
                )
            )
            return _enrolled()
        return {
            "id": auth.repo.user_id(user),
            "email": auth.repo.get(user, "email"),
            "username": auth.repo.get(user, "username"),
        }

    return router
