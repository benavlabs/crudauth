"""Unit tests for OAuthAccountService account linking (create / link existing)."""

from __future__ import annotations

from crudauth.oauth import OAuthAccountService, OAuthUserInfo
from crudauth.repository import UserRepository
from crudauth.utils import get_password_hash


async def test_oauth_creates_then_links(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel)
    service = OAuthAccountService(repo)

    info = OAuthUserInfo(
        provider="google",
        provider_user_id="g-1",
        email="Person@Example.com",
        email_verified=True,
        name="A Person",
    )
    async with sessionmaker() as db:
        user, created = await service.get_or_create_user(info, db)
        assert created is True
        assert repo.get(user, "email") == "person@example.com"
        assert repo.get(user, "google_id") == "g-1"

    # second time → same account, not created
    async with sessionmaker() as db:
        user2, created2 = await service.get_or_create_user(info, db)
        assert created2 is False
        assert repo.user_id(user2) == repo.user_id(user)


async def test_oauth_links_existing_email(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel)
    service = OAuthAccountService(repo)
    # pre-existing password user
    async with sessionmaker() as db:
        existing = await repo.create(
            db,
            {
                "email": "dup@x.com",
                "username": "dup",
                "hashed_password": get_password_hash("pw"),
            },
        )
        existing_id = repo.user_id(existing)

    info = OAuthUserInfo(
        provider="github", provider_user_id="gh-9", email="dup@x.com", email_verified=True
    )
    async with sessionmaker() as db:
        user, created = await service.get_or_create_user(info, db)
        assert created is False
        assert repo.user_id(user) == existing_id
        assert repo.get(user, "github_id") == "gh-9"
