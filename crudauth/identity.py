"""The identity contract: the login/recovery intent the model's columns can't carry.

The model owns the *shape* (which columns exist, nullable, unique);
[IdentityConfig][crudauth.identity.IdentityConfig] owns the *intent* a schema
can't express, and [CRUDAuth][crudauth.crud_auth.CRUDAuth] validates the two
against each other at construction, so a config that contradicts the model fails
loudly at startup instead of splitting into a silent second source of truth.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["IdentityConfig"]


@dataclass(frozen=True)
class IdentityConfig:
    """How an account's identity behaves, validated against the model at construction.

    Attributes:
        login: Logical fields a login identifier is matched against, in order;
            first match wins. Each must be a unique column on the model (asserted
            at construction, which is what makes first-match-wins safe).
        recovery: The single field verify/reset/change is delivered against, or
            ``None`` to disable recovery (the recovery endpoints aren't mounted).
            Must be a unique column when set.

    Example:
        ```python
        # username login, phone recovery
        CRUDAuth(..., identity=IdentityConfig(login=["username"], recovery="phone"))

        # anonymous: username login, no recovery at all
        CRUDAuth(..., identity=IdentityConfig(login=["username"], recovery=None))
        ```
    """

    login: list[str] = field(default_factory=lambda: ["email", "username"])
    recovery: str | None = "email"
