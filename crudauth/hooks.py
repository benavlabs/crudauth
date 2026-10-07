"""Lifecycle hooks - where app policy lives, never inside the package core.

App-specific side effects (welcome email, trial grant, audit logging) don't
belong in the auth flows themselves. Register them here and they fire uniformly
across *every* path - password register, OAuth, etc.
"""

from __future__ import annotations

import inspect
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Optional

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import Request

    from .oauth.schemas import OAuthUserInfo

__all__ = ["AuthHooks", "HookContext"]

logger = logging.getLogger("crudauth.hooks")

Hook = Callable[..., Optional[Awaitable[None]]]


@dataclass
class HookContext:
    """Ambient request/identity info passed to hooks as ``context=``.

    ``session_handle`` is set on a session login and logout: the same public,
    non-reversible handle ``GET /sessions`` lists, so an audit log can name the
    session that was created or ended (and match it to a revocation) without
    storing a credential.
    """

    ip_address: str | None = None
    user_agent: str | None = None
    transport: str | None = None
    request: "Request | None" = None
    extra: dict[str, Any] | None = None
    session_handle: str | None = None


async def _run_best_effort(name: str, hook: Hook | None, *args: Any, **kwargs: Any) -> bool:
    """Run ``hook``, logging what it raises; ``False`` when it raised."""
    if hook is None:
        return True
    try:
        result = hook(*args, **kwargs)
        if inspect.isawaitable(result):
            await result
    except Exception:
        logger.exception("crudauth: %s hook failed", name)
        return False
    return True


async def _run_with_db(name: str, hook: Hook | None, *args: Any, db: Any, **kwargs: Any) -> None:
    """Run a hook handed the request's ``db``, and roll back whatever it left when it raises.

    crudauth commits its own writes before any hook runs, so the rollback only undoes
    the hook's uncommitted work. Without it, a hook that failed mid-transaction would
    leave the session unusable (SQLAlchemy raises ``PendingRollbackError`` on its next
    use) for the rest of the request.
    """
    if await _run_best_effort(name, hook, *args, db=db, **kwargs):
        return
    try:
        await db.rollback()
    except Exception:
        logger.exception("crudauth: rolling back after the %s hook failed", name)


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

    Note:
        Hooks run after the operation is done (the account created, the session
        stored, the password changed), so they can't block or undo it. An
        exception a hook raises is logged on the ``crudauth.hooks`` logger with its
        traceback and the request completes normally. A hook that writes through
        ``db`` commits its own work; if it raises, crudauth rolls back whatever it
        left uncommitted, and it may roll back itself as well.
    """

    on_after_register: Hook | None = None
    on_oauth_login: Hook | None = None
    on_login_failed: Hook | None = None
    on_lockout: Hook | None = None
    on_after_login: Hook | None = None
    on_after_logout: Hook | None = None
    on_after_recovery_verified: Hook | None = None
    on_after_password_reset: Hook | None = None
    on_after_password_changed: Hook | None = None
    on_after_email_changed: Hook | None = None
    on_after_sudo: Hook | None = None
    on_after_mfa_enabled: Hook | None = None
    on_after_mfa_disabled: Hook | None = None
    on_after_recovery_code_used: Hook | None = None

    async def run_after_register(self, user: dict, *, db: Any, context: HookContext) -> None:
        await _run_with_db(
            "on_after_register", self.on_after_register, user, db=db, context=context
        )

    async def run_oauth_login(
        self,
        user: dict,
        info: "OAuthUserInfo",
        *,
        db: Any,
        created: bool,
        context: HookContext,
    ) -> None:
        """An OAuth sign-in resolved an active account: created, linked by email, or found.

        ``info`` is the provider's normalized profile (``info.username`` is the GitHub
        login, ``info.raw_data`` the provider's payload), so an app can keep provider
        data that changes over time in step on every sign-in. ``created`` is ``True``
        only when this sign-in made the account. It runs before the MFA challenge and
        before the session exists, so ``context.session_handle`` is ``None``.

        A hand-written callback that resolves the account with
        ``auth.oauth.get_or_create_user`` calls this itself, after its own checks.
        """
        await _run_with_db(
            "on_oauth_login",
            self.on_oauth_login,
            user,
            info,
            db=db,
            created=created,
            context=context,
        )

    async def run_login_failed(
        self, identifier: str, *, user: dict | None, reason: str, context: HookContext
    ) -> None:
        """A password login was refused: ``reason`` is ``"invalid_credentials"`` or ``"inactive"``.

        ``user`` is the account the identifier resolved to, or ``None`` when it named
        none. The caller's response doesn't distinguish the two; this hook can, for an
        audit log.
        """
        await _run_best_effort(
            "on_login_failed",
            self.on_login_failed,
            identifier,
            user=user,
            reason=reason,
            context=context,
        )

    async def run_lockout(self, identifier: str, *, retry_after: int, context: HookContext) -> None:
        """A password login was refused because the lockout is engaged for this IP or identifier."""
        await _run_best_effort(
            "on_lockout", self.on_lockout, identifier, retry_after=retry_after, context=context
        )

    async def run_after_login(self, user: dict, *, request: Any, context: HookContext) -> None:
        await _run_best_effort(
            "on_after_login", self.on_after_login, user, request=request, context=context
        )

    async def run_after_logout(self, user: dict, *, request: Any, context: HookContext) -> None:
        await _run_best_effort(
            "on_after_logout", self.on_after_logout, user, request=request, context=context
        )

    async def run_after_recovery_verified(
        self, user: dict, *, db: Any, context: HookContext
    ) -> None:
        await _run_with_db(
            "on_after_recovery_verified",
            self.on_after_recovery_verified,
            user,
            db=db,
            context=context,
        )

    async def run_after_password_reset(self, user: dict, *, db: Any, context: HookContext) -> None:
        await _run_with_db(
            "on_after_password_reset", self.on_after_password_reset, user, db=db, context=context
        )

    async def run_after_password_changed(
        self, user: dict, *, db: Any, context: HookContext
    ) -> None:
        await _run_with_db(
            "on_after_password_changed",
            self.on_after_password_changed,
            user,
            db=db,
            context=context,
        )

    async def run_after_email_changed(self, user: dict, *, db: Any, context: HookContext) -> None:
        await _run_with_db(
            "on_after_email_changed", self.on_after_email_changed, user, db=db, context=context
        )

    async def run_after_sudo(self, user: dict, *, request: Any, context: HookContext) -> None:
        await _run_best_effort(
            "on_after_sudo", self.on_after_sudo, user, request=request, context=context
        )

    async def run_after_mfa_enabled(self, user: dict, *, db: Any, context: HookContext) -> None:
        await _run_with_db(
            "on_after_mfa_enabled", self.on_after_mfa_enabled, user, db=db, context=context
        )

    async def run_after_mfa_disabled(self, user: dict, *, db: Any, context: HookContext) -> None:
        await _run_with_db(
            "on_after_mfa_disabled", self.on_after_mfa_disabled, user, db=db, context=context
        )

    async def run_after_recovery_code_used(
        self, user: dict, *, db: Any, context: HookContext
    ) -> None:
        await _run_with_db(
            "on_after_recovery_code_used",
            self.on_after_recovery_code_used,
            user,
            db=db,
            context=context,
        )
