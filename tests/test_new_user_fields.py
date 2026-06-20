"""``new_user_fields``: app-supplied columns merged into the single create on
both signup paths (register + oauth), gated so the callback can fill app columns
but never override crudauth's logical contract."""

from __future__ import annotations

import logging
from typing import Any

import httpx
from fastapi import FastAPI
from pydantic import BaseModel
from sqlalchemy import func, select

from crudauth import CookieConfig, CRUDAuth, NewUserContext, NewUserFields, SessionTransport
from crudauth.oauth import OAuthAccountService, OAuthUserInfo
from crudauth.repository import UserRepository

SECRET = "test-secret-key-0123456789-0123456789"


# --- unit: the gating helper ---------------------------------------------


def test_filter_provisioning_keeps_app_columns_drops_contract(UserModel, caplog) -> None:
    repo = UserRepository(UserModel)
    with caplog.at_level(logging.WARNING, logger="crudauth"):
        out = repo.filter_provisioning_data(
            {
                "full_name": "A",  # app column -> kept
                "role": "staff",  # app column -> kept
                "email": "x@y.com",  # contract -> dropped
                "hashed_password": "h",  # contract -> dropped
                "is_superuser": True,  # contract -> dropped
                "id": 9,  # contract -> dropped
            }
        )
    assert out == {"full_name": "A", "role": "staff"}
    assert "new_user_fields" in caplog.text
    assert "is_superuser" in caplog.text


def test_filter_provisioning_warns_once_per_key(UserModel, caplog) -> None:
    # A standing misconfiguration (same gated key dropped every signup) must not
    # flood the logs: warn once per distinct key, then stay quiet.
    repo = UserRepository(UserModel)
    with caplog.at_level(logging.WARNING, logger="crudauth"):
        repo.filter_provisioning_data({"is_superuser": True, "role": "a"})
        repo.filter_provisioning_data({"is_superuser": True, "role": "b"})  # same key again
    assert caplog.text.count("new_user_fields") == 1  # only the first drop warned
    # a *different* gated key still warns (it's new)
    with caplog.at_level(logging.WARNING, logger="crudauth"):
        caplog.clear()
        repo.filter_provisioning_data({"email_verified": True})
    assert "email_verified" in caplog.text


def test_filter_provisioning_respects_column_map(UserModel) -> None:
    # is_superuser aliased to is_admin: returning the mapped name is dropped too,
    # closing the alias hole.
    repo = UserRepository(UserModel, column_map={"is_superuser": "is_admin"})
    out = repo.filter_provisioning_data({"is_admin": True, "role": "staff"})
    assert out == {"role": "staff"}


# --- register path --------------------------------------------------------


async def _register(
    get_session,
    UserModel,
    callback: NewUserFields | None,
    defaults: dict[str, Any] | None = None,
) -> httpx.Response:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        new_user_fields=callback,
        new_user_defaults=defaults,
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as c:
            return await c.post(
                "/register",
                json={"email": "new@x.com", "username": "new", "password": "pw123456"},
            )
    finally:
        await auth.shutdown()


async def test_register_runs_callback_and_sets_app_columns(
    get_session, UserModel, sessionmaker
) -> None:
    seen: list[NewUserContext] = []

    def fields(ctx: NewUserContext) -> dict[str, Any]:
        seen.append(ctx)
        return {"full_name": ctx.email.split("@")[0], "role": "staff"}

    r = await _register(get_session, UserModel, fields)
    assert r.status_code == 200, r.text

    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "new@x.com")
    assert user is not None
    assert user.full_name == "new"
    assert user.role == "staff"

    assert seen[0].source == "register"
    assert seen[0].oauth is None
    body = seen[0].register_data
    assert body is not None and body["username"] == "new" and "password" not in body


async def test_register_callback_cannot_override_contract(
    get_session, UserModel, sessionmaker, caplog
) -> None:
    def fields(ctx: NewUserContext) -> dict[str, Any]:
        return {
            "role": "staff",
            "is_superuser": True,
            "email_verified": True,
            "email": "evil@x.com",
        }

    with caplog.at_level(logging.WARNING, logger="crudauth"):
        r = await _register(get_session, UserModel, fields)
    assert r.status_code == 200, r.text

    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "new@x.com")
    assert user is not None
    assert user.role == "staff"  # app column set
    assert user.is_superuser is False  # contract field NOT overridden
    assert user.email_verified is False
    assert user.email == "new@x.com"  # not the callback's "evil@x.com"
    assert "new_user_fields" in caplog.text


async def test_register_async_callback(get_session, UserModel, sessionmaker) -> None:
    async def fields(ctx: NewUserContext) -> dict[str, Any]:
        return {"role": "async-set"}

    r = await _register(get_session, UserModel, fields)
    assert r.status_code == 200, r.text

    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "new@x.com")
    assert user is not None
    assert user.role == "async-set"


async def test_register_without_callback_uses_model_defaults(
    get_session, UserModel, sessionmaker
) -> None:
    r = await _register(get_session, UserModel, None)
    assert r.status_code == 200, r.text

    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "new@x.com")
    assert user is not None
    assert user.role == "user"  # the column default, untouched
    assert user.full_name is None


# --- oauth path -----------------------------------------------------------


async def test_oauth_signup_runs_callback(sessionmaker, UserModel) -> None:
    seen: list[NewUserContext] = []

    def fields(ctx: NewUserContext) -> dict[str, Any]:
        seen.append(ctx)
        assert ctx.oauth is not None
        return {"role": "oauth-user", "full_name": ctx.oauth.name}

    repo = UserRepository(UserModel)
    service = OAuthAccountService(repo, fields)
    info = OAuthUserInfo(
        provider="google",
        provider_user_id="g-1",
        email="o@x.com",
        email_verified=True,
        name="O Person",
    )
    async with sessionmaker() as db:
        user, created = await service.get_or_create_user(info, db)
    assert created is True
    assert repo.get(user, "role") == "oauth-user"
    assert repo.get(user, "full_name") == "O Person"

    assert seen[0].source == "oauth"
    assert seen[0].register_data is None
    o = seen[0].oauth
    assert o is not None and o.provider == "google"


async def test_oauth_link_existing_skips_callback(sessionmaker, UserModel) -> None:
    from crudauth.utils import get_password_hash

    calls: list[NewUserContext] = []

    def fields(ctx: NewUserContext) -> dict[str, Any]:
        calls.append(ctx)
        return {"role": "should-not-apply"}

    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        await repo.create(
            db,
            {"email": "dup@x.com", "username": "dup", "hashed_password": get_password_hash("pw")},
        )

    service = OAuthAccountService(repo, fields)
    info = OAuthUserInfo(
        provider="github", provider_user_id="gh-9", email="dup@x.com", email_verified=True
    )
    async with sessionmaker() as db:
        user, created = await service.get_or_create_user(info, db)
    assert created is False  # linked, not created
    assert repo.get(user, "role") == "user"  # callback never ran
    assert calls == []


# --- new_user_defaults (the declarative constant knob) --------------------


def test_defaults_gated_at_construction(get_session, UserModel, caplog) -> None:
    # A crudauth-owned key in the constants is dropped + warned ONCE, at build time.
    with caplog.at_level(logging.WARNING, logger="crudauth"):
        auth = CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY=SECRET,
            transports=[SessionTransport(cookies=CookieConfig(secure=False))],
            new_user_defaults={"role": "staff", "is_superuser": True},
        )
    assert auth._new_user_defaults == {"role": "staff"}  # is_superuser dropped
    assert "new_user_fields" in caplog.text


async def test_register_applies_defaults(get_session, UserModel, sessionmaker) -> None:
    r = await _register(get_session, UserModel, None, defaults={"role": "from-defaults"})
    assert r.status_code == 200, r.text
    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "new@x.com")
    assert user is not None
    assert user.role == "from-defaults"


async def test_callback_overrides_defaults(get_session, UserModel, sessionmaker) -> None:
    def fields(ctx: NewUserContext) -> dict[str, Any]:
        return {"role": "from-callback"}

    r = await _register(get_session, UserModel, fields, defaults={"role": "from-defaults"})
    assert r.status_code == 200, r.text
    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "new@x.com")
    assert user is not None
    assert user.role == "from-callback"  # callback merged after defaults


# --- BaseModel return + ctx.db + suggested_name ---------------------------


async def test_callback_can_return_basemodel(get_session, UserModel, sessionmaker) -> None:
    class Provision(BaseModel):
        role: str = "from-model"
        is_superuser: bool = True  # contract field on the model -> dropped after dump

    def fields(ctx: NewUserContext) -> BaseModel:
        return Provision()

    r = await _register(get_session, UserModel, fields)
    assert r.status_code == 200, r.text
    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "new@x.com")
    assert user is not None
    assert user.role == "from-model"
    assert user.is_superuser is False  # typed contract field still gated


async def test_callback_can_read_ctx_db(get_session, UserModel, sessionmaker) -> None:
    # The first-registered user becomes the owner, decided by a live query on ctx.db.
    async def fields(ctx: NewUserContext) -> dict[str, Any]:
        existing = await ctx.db.scalar(select(func.count()).select_from(UserModel))
        return {"role": "owner" if existing == 0 else "member"}

    r = await _register(get_session, UserModel, fields)
    assert r.status_code == 200, r.text
    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "new@x.com")
    assert user is not None
    assert user.role == "owner"


async def test_suggested_name(sessionmaker) -> None:
    async with sessionmaker() as db:
        info = OAuthUserInfo(
            provider="google", provider_user_id="g", email="a@x.com", name="Full Name"
        )
        oauth_ctx = NewUserContext(email="a@x.com", username="a", source="oauth", db=db, oauth=info)
        assert oauth_ctx.suggested_name == "Full Name"
        reg_ctx = NewUserContext(email="alice@x.com", username="a", source="register", db=db)
        assert reg_ctx.suggested_name == "alice"
        # email-less (anonymous) shape falls back to the username, not ""
        anon_ctx = NewUserContext(email="", username="neo", source="register", db=db)
        assert anon_ctx.suggested_name == "neo"


# --- mass-assignment: neither knob can grant privilege, on either path ----


async def test_defaults_cannot_grant_privilege_on_register(
    get_session, UserModel, sessionmaker
) -> None:
    r = await _register(
        get_session,
        UserModel,
        None,
        defaults={"role": "staff", "is_superuser": True, "email_verified": True},
    )
    assert r.status_code == 200, r.text
    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "new@x.com")
    assert user is not None
    assert user.role == "staff"
    assert user.is_superuser is False
    assert user.email_verified is False


async def test_callback_cannot_grant_privilege_on_oauth(sessionmaker, UserModel) -> None:
    def fields(ctx: NewUserContext) -> dict[str, Any]:
        return {"role": "staff", "is_superuser": True, "email_verified": False}

    repo = UserRepository(UserModel)
    service = OAuthAccountService(repo, fields)
    info = OAuthUserInfo(
        provider="google", provider_user_id="g-2", email="ev@x.com", email_verified=True, name="Ev"
    )
    async with sessionmaker() as db:
        user, created = await service.get_or_create_user(info, db)
    assert created is True
    assert repo.get(user, "role") == "staff"
    assert repo.is_superuser(user) is False
    assert (
        repo.email_verified(user) is True
    )  # crudauth's value (provider-verified), not the callback's


async def test_oauth_applies_defaults(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel)
    service = OAuthAccountService(repo, None, {"role": "oauth-default"})
    info = OAuthUserInfo(
        provider="github", provider_user_id="gh-1", email="d@x.com", email_verified=True
    )
    async with sessionmaker() as db:
        user, created = await service.get_or_create_user(info, db)
    assert created is True
    assert repo.get(user, "role") == "oauth-default"
