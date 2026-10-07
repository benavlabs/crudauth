"""Recovery tokens stop working once the account state they were issued for changes."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from crudauth import (
    CookieConfig,
    CRUDAuth,
    DeliveryChannel,
    DeliveryIntent,
    EmailConfig,
    EmailSender,
    SessionTransport,
)
from crudauth.repository import UserRepository
from tests.conftest import mounted_paths

SECRET = "test-secret-key-0123456789-0123456789"
PASSWORD = "pw123456"


class CapturingSender(EmailSender):
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    async def send(self, *, to, subject, body, kind, context):
        self.sent.append({"to": to, "kind": kind, "token": body.split("token=")[-1]})

    def token_for(self, kind: str) -> str:
        return next(msg["token"] for msg in reversed(self.sent) if msg["kind"] == kind)


class RecordingChannel(DeliveryChannel):
    def __init__(self) -> None:
        self.kinds: list[str] = []

    async def deliver(self, intent: DeliveryIntent, db) -> None:
        self.kinds.append(intent.kind)


@pytest.fixture
async def app_parts(get_session, UserModel):
    sender = CapturingSender()
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        email=EmailConfig(sender=sender, frontend_url="https://app.example.com"),
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    yield app, sender
    await auth.shutdown()


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def _signed_in(client: httpx.AsyncClient, password: str = PASSWORD) -> dict[str, str]:
    login = await client.post("/login", data={"username": "alice", "password": password})
    return {"X-CSRF-Token": login.json()["csrf_token"]}


async def _register(client: httpx.AsyncClient) -> None:
    await client.post(
        "/register", json={"email": "a@x.com", "username": "alice", "password": PASSWORD}
    )


async def _request_change(client: httpx.AsyncClient, headers: dict[str, str]) -> None:
    await client.post(
        "/email/change-request",
        json={"new_email": "attacker@x.com", "password": PASSWORD},
        headers=headers,
    )


async def _reset(client: httpx.AsyncClient, sender: CapturingSender, password: str) -> None:
    await client.post("/password/reset-request", json={"email": "a@x.com"})
    response = await client.post(
        "/password/reset-confirm",
        json={"token": sender.token_for("reset_password"), "new_password": password},
    )
    assert response.status_code == 200


async def test_an_email_change_token_dies_with_a_password_reset(app_parts) -> None:
    app, sender = app_parts
    async with _client(app) as attacker, _client(app) as owner:
        await _register(attacker)
        await _request_change(attacker, await _signed_in(attacker))
        change_token = sender.token_for("change_email")
        await _reset(owner, sender, "owner-recovered-1")
        confirm = await owner.post("/email/change-confirm", json={"token": change_token})

    assert (confirm.status_code, confirm.json()) == (400, {"detail": "Invalid or expired token"})


async def test_an_email_change_token_dies_with_a_password_change(app_parts) -> None:
    app, sender = app_parts
    async with _client(app) as client:
        await _register(client)
        headers = await _signed_in(client)
        await _request_change(client, headers)
        change_token = sender.token_for("change_email")
        await client.post(
            "/change-password",
            json={"current_password": PASSWORD, "new_password": "changed-pw-1"},
            headers=headers,
        )
        confirm = await client.post("/email/change-confirm", json={"token": change_token})

    assert confirm.status_code == 400


async def test_a_reset_token_dies_once_the_password_changes(app_parts) -> None:
    app, sender = app_parts
    async with _client(app) as client:
        await _register(client)
        await client.post("/password/reset-request", json={"email": "a@x.com"})
        reset_token = sender.token_for("reset_password")
        await client.post(
            "/change-password",
            json={"current_password": PASSWORD, "new_password": "changed-pw-1"},
            headers=await _signed_in(client),
        )
        replay = await client.post(
            "/password/reset-confirm",
            json={"token": reset_token, "new_password": "stale-link-pw-1"},
        )
        stale_login = await client.post(
            "/login", data={"username": "alice", "password": "stale-link-pw-1"}
        )

    assert (replay.status_code, stale_login.status_code) == (400, 401)


async def test_a_reset_token_dies_with_an_email_change(app_parts) -> None:
    app, sender = app_parts
    async with _client(app) as client:
        await _register(client)
        await client.post("/password/reset-request", json={"email": "a@x.com"})
        reset_token = sender.token_for("reset_password")
        headers = await _signed_in(client)
        await client.post(
            "/email/change-request",
            json={"new_email": "new@x.com", "password": PASSWORD},
            headers=headers,
        )
        await client.post("/email/change-confirm", json={"token": sender.token_for("change_email")})
        replay = await client.post(
            "/password/reset-confirm",
            json={"token": reset_token, "new_password": "old-address-pw-1"},
        )

    assert replay.status_code == 400


async def test_a_verification_token_dies_when_the_address_changes(
    app_parts, sessionmaker, UserModel
) -> None:
    app, sender = app_parts
    repo = UserRepository(UserModel)
    async with _client(app) as client:
        await _register(client)
        verify_token = sender.token_for("verify_email")
        async with sessionmaker() as db:
            user = await repo.get_by_email(db, "a@x.com")
            await repo.update(db, user, {"email": "unproven@x.com"})
        confirm = await client.post("/email/verify-confirm", json={"token": verify_token})

    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "unproven@x.com")
    assert confirm.status_code == 400
    assert repo.email_verified(user) is False


async def test_a_confirmed_change_notifies_the_previous_address(app_parts) -> None:
    app, sender = app_parts
    async with _client(app) as client:
        await _register(client)
        await _request_change(client, await _signed_in(client))
        await client.post("/email/change-confirm", json={"token": sender.token_for("change_email")})

    notices = [msg for msg in sender.sent if msg["kind"] == "email_changed"]
    assert [msg["to"] for msg in notices] == ["a@x.com"]


async def test_change_email_only_reaches_channels_that_email_the_recipient(
    get_session, UserModel
) -> None:
    sender = CapturingSender()
    other = RecordingChannel()
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        email=EmailConfig(sender=sender, frontend_url="https://app.example.com"),
        channels=[other],
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with _client(app) as client:
        await _register(client)
        await _request_change(client, await _signed_in(client))
    await auth.shutdown()

    assert "change_email" in [msg["kind"] for msg in sender.sent]
    assert "change_email" not in other.kinds
    assert "verify_email" in other.kinds


def test_change_email_routes_need_a_channel_that_emails_the_recipient(
    get_session, UserModel
) -> None:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        channels=[RecordingChannel()],
    )
    paths = mounted_paths(auth.router)

    assert "/password/reset-request" in paths
    assert "/email/change-request" not in paths


async def _disable(sessionmaker, repo: UserRepository, email: str = "a@x.com") -> None:
    async with sessionmaker() as db:
        await repo.update(db, await repo.get_by_email(db, email), {"is_active": False})


@pytest.mark.parametrize(
    ("route", "kind"),
    [("/password/reset-request", "reset_password"), ("/email/verify-request", "verify_email")],
    ids=["reset", "verification"],
)
async def test_an_inactive_account_is_sent_nothing_and_answered_like_an_unknown_one(
    app_parts, sessionmaker, UserModel, route, kind
) -> None:
    app, sender = app_parts
    repo = UserRepository(UserModel)
    async with _client(app) as client:
        await _register(client)
        await _disable(sessionmaker, repo)
        sender.sent.clear()
        inactive = await client.post(route, json={"email": "a@x.com"})
        unknown = await client.post(route, json={"email": "nobody@x.com"})

    assert [msg["kind"] for msg in sender.sent] == []
    assert (inactive.status_code, inactive.json()) == (unknown.status_code, unknown.json())


async def test_a_reset_link_stops_working_once_the_account_is_disabled(
    app_parts, sessionmaker, UserModel
) -> None:
    app, sender = app_parts
    repo = UserRepository(UserModel)
    async with _client(app) as client:
        await _register(client)
        await client.post("/password/reset-request", json={"email": "a@x.com"})
        reset_token = sender.token_for("reset_password")
        await _disable(sessionmaker, repo)
        confirm = await client.post(
            "/password/reset-confirm",
            json={"token": reset_token, "new_password": "after-disable-1"},
        )

    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "a@x.com")
    assert (confirm.status_code, confirm.json()) == (400, {"detail": "Invalid or expired token"})
    assert repo.token_version(user) == 0


async def test_a_verification_link_stops_working_once_the_account_is_disabled(
    app_parts, sessionmaker, UserModel
) -> None:
    app, sender = app_parts
    repo = UserRepository(UserModel)
    async with _client(app) as client:
        await _register(client)
        verify_token = sender.token_for("verify_email")
        await _disable(sessionmaker, repo)
        confirm = await client.post("/email/verify-confirm", json={"token": verify_token})

    async with sessionmaker() as db:
        user = await repo.get_by_email(db, "a@x.com")
    assert confirm.status_code == 400
    assert repo.email_verified(user) is False


async def test_an_email_change_link_stops_working_once_the_account_is_disabled(
    app_parts, sessionmaker, UserModel
) -> None:
    app, sender = app_parts
    repo = UserRepository(UserModel)
    async with _client(app) as client:
        await _register(client)
        await _request_change(client, await _signed_in(client))
        change_token = sender.token_for("change_email")
        await _disable(sessionmaker, repo)
        confirm = await client.post("/email/change-confirm", json={"token": change_token})

    async with sessionmaker() as db:
        unchanged = await repo.get_by_email(db, "a@x.com")
    assert confirm.status_code == 400
    assert unchanged is not None
    assert [msg["kind"] for msg in sender.sent].count("email_changed") == 0
