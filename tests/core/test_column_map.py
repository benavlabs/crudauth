"""Map the contract onto an existing table with different column names (cookbook A2)."""

from __future__ import annotations

import httpx
import pytest
from fastapi import Depends, FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from crudauth import CRUDAuth, CookieConfig, Principal, SessionTransport


class LegacyBase(DeclarativeBase):
    pass


class LegacyAccount(LegacyBase):
    __tablename__ = "accounts"

    account_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    email_address: Mapped[str] = mapped_column(unique=True)
    username: Mapped[str] = mapped_column(unique=True)
    pw_hash: Mapped[str] = mapped_column()
    enabled: Mapped[bool] = mapped_column(default=True)


COLUMN_MAP = {
    "id": "account_id",
    "email": "email_address",
    "hashed_password": "pw_hash",
    "is_active": "enabled",
}


@pytest.fixture
async def client():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(LegacyBase.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def get_session():
        async with maker() as session:
            yield session

    auth = CRUDAuth(
        session=get_session,
        user_model=LegacyAccount,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        column_map=COLUMN_MAP,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
    )
    app = FastAPI()
    app.include_router(auth.router)

    @app.get("/whoami")
    async def whoami(user: Principal = Depends(auth.current_user())):
        return {"id": user.user_id, "email": user.user.email_address}

    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c
    await auth.shutdown()
    await engine.dispose()


async def test_legacy_schema_register_login_me(client) -> None:
    r = await client.post(
        "/register",
        json={"email": "legacy@x.com", "username": "legacy", "password": "pw123456"},
    )
    assert r.status_code == 200, r.text

    r = await client.post("/login", data={"username": "legacy", "password": "pw123456"})
    assert r.status_code == 200, r.text

    r = await client.get("/whoami")
    assert r.status_code == 200
    assert r.json()["email"] == "legacy@x.com"
