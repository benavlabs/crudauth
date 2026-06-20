"""Lifecycle hooks - where app policy lives, never inside the package core.

App-specific side effects (welcome email, trial grant, audit logging) don't
belong in the auth flows themselves. Register them here and they fire uniformly
across *every* path - password register, OAuth, etc.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Optional

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import Request

__all__ = ["AuthHooks", "HookContext"]

Hook = Callable[..., Optional[Awaitable[None]]]


@dataclass
class HookContext:
    """Ambient request/identity info passed to hooks as ``context=``."""

    ip_address: str | None = None
    user_agent: str | None = None
    transport: str | None = None
    request: "Request | None" = None
    extra: dict[str, Any] | None = None


async def _maybe_await(result: Any) -> None:
    if inspect.isawaitable(result):
        await result


@dataclass
class AuthHooks:
    """Container of optional lifecycle callbacks.

    Every hook may be sync or async. ``user`` is passed as a plain ``dict`` so
    hooks don't depend on your ORM type. Example:

        ```python
        async def after_register(user, *, db, context):
            await grant_trial(user["id"], db=db)

        AuthHooks(on_after_register=after_register)
        ```
    """

    on_after_register: Hook | None = None
    on_after_login: Hook | None = None
    on_after_logout: Hook | None = None
    on_after_recovery_verified: Hook | None = None
    on_after_password_reset: Hook | None = None
    on_after_email_changed: Hook | None = None
    on_after_sudo: Hook | None = None

    async def run_after_register(self, user: dict, *, db: Any, context: HookContext) -> None:
        if self.on_after_register is not None:
            await _maybe_await(self.on_after_register(user, db=db, context=context))

    async def run_after_login(self, user: dict, *, request: Any, context: HookContext) -> None:
        if self.on_after_login is not None:
            await _maybe_await(self.on_after_login(user, request=request, context=context))

    async def run_after_logout(self, user: dict, *, request: Any, context: HookContext) -> None:
        if self.on_after_logout is not None:
            await _maybe_await(self.on_after_logout(user, request=request, context=context))

    async def run_after_recovery_verified(
        self, user: dict, *, db: Any, context: HookContext
    ) -> None:
        if self.on_after_recovery_verified is not None:
            await _maybe_await(self.on_after_recovery_verified(user, db=db, context=context))

    async def run_after_password_reset(self, user: dict, *, db: Any, context: HookContext) -> None:
        if self.on_after_password_reset is not None:
            await _maybe_await(self.on_after_password_reset(user, db=db, context=context))

    async def run_after_email_changed(self, user: dict, *, db: Any, context: HookContext) -> None:
        if self.on_after_email_changed is not None:
            await _maybe_await(self.on_after_email_changed(user, db=db, context=context))

    async def run_after_sudo(self, user: dict, *, request: Any, context: HookContext) -> None:
        if self.on_after_sudo is not None:
            await _maybe_await(self.on_after_sudo(user, request=request, context=context))
