"""Email flows: verify / reset, with a capturing EmailSender and hooks."""

from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI

from crudauth import AuthHooks, CookieConfig, CRUDAuth, EmailConfig, EmailSender, SessionTransport
from crudauth.email.service import EmailFlowService
from crudauth.repository import UserRepository
from crudauth.utils import get_password_hash


class CapturingSender(EmailSender):
    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def send(self, *, to, subject, body, kind):
        self.sent.append({"to": to, "subject": subject, "body": body, "kind": kind})

    def token_for(self, kind):
        for msg in reversed(self.sent):
            if msg["kind"] == kind:
                return msg["body"].split("token=")[-1]
        raise AssertionError(f"no {kind} email captured")


@pytest.fixture
async def ctx(get_session, UserModel):
    sender = CapturingSender()
    welcomed = []

    async def after_register(user, *, db, context):
        welcomed.append(user["email"])

    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY="test-secret-key-0123456789-0123456789",
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        email=EmailConfig(sender=sender, frontend_url="https://app.example.com"),
        hooks=AuthHooks(on_after_register=after_register),
    )
    app = FastAPI()
    app.include_router(auth.router)
    await auth.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c, sender, welcomed
    await auth.shutdown()


async def _register(client):
    await client.post(
        "/register", json={"email": "a@x.com", "username": "alice", "password": "pw123456"}
    )


async def test_register_fires_after_register_hook(ctx) -> None:
    client, sender, welcomed = ctx
    await _register(client)
    assert welcomed == ["a@x.com"]


async def test_email_change_round_trip(ctx) -> None:
    client, sender, _ = ctx
    await _register(client)
    login = await client.post("/login", data={"username": "alice", "password": "pw123456"})
    csrf = login.json()["csrf_token"]

    # change-request is an authenticated POST → session transport enforces CSRF
    r = await client.post(
        "/email/change-request",
        json={"new_email": "alice2@x.com", "password": "pw123456"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200

    token = sender.token_for("change_email")
    r = await client.post("/email/change-confirm", json={"token": token})
    assert r.status_code == 200

    # /me now reflects the new address
    me = await client.get("/me")
    assert me.json()["email"] == "alice2@x.com"


async def test_confirm_email_change_marks_verified(sessionmaker, UserModel) -> None:
    # Clicking the link from the NEW address proves control of it, so the change
    # confirmation marks the email verified - even if the account was unverified.
    repo = UserRepository(UserModel)
    sender = CapturingSender()
    svc = EmailFlowService(
        repo=repo,
        secret_key="test-secret-key-0123456789-0123456789",
        config=EmailConfig(sender=sender, frontend_url="https://app"),
        hooks=AuthHooks(),
    )
    async with sessionmaker() as db:
        user = await repo.create(
            db, {"email": "old@x.com", "username": "u", "hashed_password": get_password_hash("pw")}
        )
        assert repo.email_verified(user) is False
        await svc.request_email_change(db, user, "new@x.com", "pw")

    token = sender.token_for("change_email")
    async with sessionmaker() as db:
        updated = await svc.confirm_email_change(db, token)
    assert repo.get(updated, "email") == "new@x.com"
    assert repo.email_verified(updated) is True


async def test_email_change_wrong_password_rejected(ctx) -> None:
    client, _, _ = ctx
    await _register(client)
    login = await client.post("/login", data={"username": "alice", "password": "pw123456"})
    csrf = login.json()["csrf_token"]
    r = await client.post(
        "/email/change-request",
        json={"new_email": "alice2@x.com", "password": "wrong"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 400


async def test_verify_email_flow(ctx) -> None:
    client, sender, _ = ctx
    await _register(client)
    r = await client.post("/verify-email/request", json={"email": "a@x.com"})
    assert r.status_code == 200
    token = sender.token_for("verify_email")
    r = await client.post("/verify-email/confirm", json={"token": token})
    assert r.status_code == 200
    # replay is rejected (one-time use)
    r = await client.post("/verify-email/confirm", json={"token": token})
    assert r.status_code == 400


async def test_password_reset_flow(ctx) -> None:
    client, sender, _ = ctx
    await _register(client)
    r = await client.post("/password/request-reset", json={"email": "a@x.com"})
    assert r.status_code == 200
    token = sender.token_for("reset_password")
    r = await client.post("/password/reset", json={"token": token, "new_password": "newpw12345"})
    assert r.status_code == 200
    # old password no longer works, new one does
    assert (
        await client.post("/login", data={"username": "alice", "password": "pw123456"})
    ).status_code == 401
    assert (
        await client.post("/login", data={"username": "alice", "password": "newpw12345"})
    ).status_code == 200


async def test_reset_request_idempotent_for_unknown_email(ctx) -> None:
    client, sender, _ = ctx
    r = await client.post("/password/request-reset", json={"email": "ghost@x.com"})
    assert r.status_code == 200  # no enumeration
    assert sender.sent == []
