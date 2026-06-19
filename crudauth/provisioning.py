"""App-supplied fields for new-user creation (server-side, both signup paths).

crudauth inserts the user row itself, on ``/register`` and on OAuth signup, from
the logical fields it owns (``email``, ``username``, ``hashed_password``, the
oauth linkage). A real app's user table is usually wider than that contract and
often has columns that are ``NOT NULL`` with no default (``name``, ``tier_id``,
...). ``new_user_fields`` is the seam that lets the app contribute those columns
to the same insert, on both signup paths, without crudauth dictating the model's
shape.

The callback is fed a *trusted* [NewUserContext][crudauth.provisioning.NewUserContext]
that crudauth builds - never the raw request body, so a client can't smuggle a
column value through it. It returns app columns only (as a ``dict`` or a
``BaseModel``): any crudauth logical field it tries to set (by logical or mapped
column name) is dropped, so it can fill the app's own columns but never override
identity, privilege, or state crudauth is authoritative for. See
[UserRepository.filter_provisioning_data][crudauth.repository.UserRepository.filter_provisioning_data].
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Literal, Union

from pydantic import BaseModel

if TYPE_CHECKING:  # pragma: no cover
    from sqlalchemy.ext.asyncio import AsyncSession

    from .oauth.schemas import OAuthUserInfo
    from .repository import UserRepository

__all__ = ["NewUserContext", "NewUserFields", "resolve_new_user_fields"]


@dataclass(frozen=True)
class NewUserContext:
    """What crudauth knows about a user it is about to create.

    Fed to ``new_user_fields`` on both signup paths. Server-built and trusted -
    never the raw request body.

    Attributes:
        email: The new user's (canonicalized) email.
        username: The final username, after OAuth uniquification.
        source: ``"register"`` for password signup, ``"oauth"`` for OAuth signup.
        db: The active session. The callback may read from it (e.g. to resolve a
            default tier or assign an org by email domain) but must NOT commit -
            crudauth owns the transaction boundary.
        register_data: The validated ``/register`` body (password excluded), or
            ``None`` on the OAuth path.
        oauth: The provider profile, or ``None`` on the password path.
    """

    email: str
    username: str
    source: Literal["register", "oauth"]
    db: AsyncSession
    register_data: dict[str, Any] | None = None
    oauth: OAuthUserInfo | None = None

    @property
    def suggested_name(self) -> str:
        """A display name to default to: the OAuth name if present, else the
        email local-part."""
        if self.oauth is not None and self.oauth.name:
            return self.oauth.name
        return self.email.split("@")[0]


NewUserFields = Callable[
    [NewUserContext], Union[BaseModel, dict[str, Any], Awaitable[Union[BaseModel, dict[str, Any]]]]
]


async def resolve_new_user_fields(
    callback: NewUserFields | None,
    context: NewUserContext,
    repo: UserRepository,
) -> dict[str, Any]:
    """Run ``callback`` (sync or async), normalize its return, and gate it.

    Returns an empty dict when ``callback`` is ``None``. A returned ``BaseModel``
    is ``model_dump()``-ed first, then the dict is filtered through
    [filter_provisioning_data][crudauth.repository.UserRepository.filter_provisioning_data]
    so a typed field naming a crudauth column is dropped exactly like a dict key.
    """
    if callback is None:
        return {}
    result = callback(context)
    if inspect.isawaitable(result):
        result = await result
    data = result.model_dump() if isinstance(result, BaseModel) else dict(result)
    return repo.filter_provisioning_data(data)
