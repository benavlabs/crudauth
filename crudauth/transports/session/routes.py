"""The session transport's own routes: ``/login`` and ``/logout``."""

from typing import TYPE_CHECKING, Annotated, Any

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.security import OAuth2PasswordRequestForm

from ...exceptions import ForbiddenException
from ...utils import is_cross_site
from ..login import password_login

if TYPE_CHECKING:  # pragma: no cover
    from .transport import SessionTransport

__all__ = ["build_session_routes"]


def build_session_routes(transport: "SessionTransport") -> APIRouter:
    """Build the routes a bound [SessionTransport][crudauth.transports.session.transport.SessionTransport] contributes."""
    router = APIRouter(tags=["auth"])
    runtime = transport.runtime
    db_dep = runtime.db_dependency
    manager = transport.manager
    assert manager is not None

    @router.post("/login")
    async def login(
        request: Request,
        response: Response,
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
        db: Annotated[Any, Depends(db_dep)],
        remember_me: Annotated[bool, Form()] = False,
    ):
        """Log in with username/email + password; sets the session + CSRF cookies.

        Subject to login lockout (shared with bearer ``/token``). ``remember_me``
        switches the cookie from session-scoped to a long persistent lifetime.
        A request the browser marks ``Sec-Fetch-Site: cross-site`` gets a 403,
        so another site can't sign the visitor into an account it controls.

        Note:
            A disabled account returns the same "Incorrect username or
            password" as bad credentials, so a credential holder can't tell a
            disabled account from a wrong password; the real reason is logged
            server-side (``reason=disabled``) for operators.
        """
        if is_cross_site(request):
            raise ForbiddenException("Cross-site login requests are not allowed.")
        return await password_login(
            transport,
            db=db,
            request=request,
            response=response,
            form_data=form_data,
            options={"remember_me": remember_me},
        )

    @router.post("/logout")
    async def logout(request: Request, response: Response, db: Annotated[Any, Depends(db_dep)]):
        """Revoke the current session and clear the auth cookies (CSRF-protected).

        Clears every configured transport's cookies, including a bearer refresh
        cookie. A session that already expired has nothing left to protect, so
        its cookies are cleared without a CSRF check. The body of
        [complete_logout][crudauth.transports.session.transport.SessionTransport.complete_logout].
        """
        await transport.complete_logout(request, response, db)
        return {"detail": "Logged out"}

    return router
