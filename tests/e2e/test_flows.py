"""End-to-end user journeys against real Postgres.

The anchor for the toolbox refactor: these exercise login / token / refresh /
lockout / revocation (the paths the extraction touches) plus the surrounding
flows, end to end over HTTP, so before and after must be byte-for-byte identical.
"""

from __future__ import annotations

from typing import Any

import httpx


async def _register(client: httpx.AsyncClient, **over: Any) -> httpx.Response:
    body = {"email": "a@x.com", "username": "alice", "password": "pw123456"}
    body.update(over)
    return await client.post("/register", json=body)


async def test_session_password_lifecycle(app_ctx: Any) -> None:
    auth, client, maker, channel = app_ctx
    assert (await _register(client, full_name="Alice")).status_code == 202  # recovery enrolled

    login = await client.post("/login", data={"username": "alice", "password": "pw123456"})
    assert login.status_code == 200
    csrf = login.json()["csrf_token"]
    assert (await client.get("/me")).status_code == 200

    changed = await client.post(
        "/change-password",
        headers={"X-CSRF-Token": csrf},
        json={"current_password": "pw123456", "new_password": "new-pw-123"},
    )
    assert changed.status_code == 200

    logout = await client.post("/logout", headers={"X-CSRF-Token": csrf})
    assert logout.status_code == 200
    assert (await client.get("/me")).status_code == 401

    assert (
        await client.post("/login", data={"username": "alice", "password": "pw123456"})
    ).status_code == 401
    assert (
        await client.post("/login", data={"username": "alice", "password": "new-pw-123"})
    ).status_code == 200


async def test_bearer_token_refresh_and_revocation(app_ctx: Any) -> None:
    auth, client, maker, channel = app_ctx
    await _register(client, email="b@x.com", username="bob")

    tok = await client.post("/token", data={"username": "bob", "password": "pw123456"})
    assert tok.status_code == 200
    body = tok.json()
    access = body["access_token"]

    # bearer auth round-trips: proves the string `sub` coerces to the int PK on Postgres
    me = await client.get("/me", headers={"Authorization": f"Bearer {access}"})
    assert me.status_code == 200

    # refresh mints a fresh, working access token
    refreshed = await client.post("/refresh", json={"refresh_token": body["refresh_token"]})
    assert refreshed.status_code == 200
    new_access = refreshed.json()["access_token"]
    assert (
        await client.get("/me", headers={"Authorization": f"Bearer {new_access}"})
    ).status_code == 200

    # a password reset bumps token_version -> the old access token is revoked
    assert (
        await client.post("/password/reset-request", json={"email": "b@x.com"})
    ).status_code in (200, 202)
    reset = next(i for i in reversed(channel.intents) if i.kind == "reset_password")
    confirm = await client.post(
        "/password/reset-confirm", json={"token": reset.token, "new_password": "reset-pw-1"}
    )
    assert confirm.status_code == 200
    assert (
        await client.get("/me", headers={"Authorization": f"Bearer {new_access}"})
    ).status_code == 401


async def test_shared_login_lockout(app_factory: Any) -> None:
    # Tight cap so a few wrong posts trip lockout; lockout is shared, so once
    # /login is locked, /token is locked too.
    app, auth, channel = app_factory(login_max_attempts=2)
    await auth.initialize()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            await _register(client, email="c@x.com", username="carol")
            statuses = [
                (
                    await client.post("/login", data={"username": "carol", "password": "nope"})
                ).status_code
                for _ in range(3)
            ]
            assert statuses[0] == 401  # bad creds before the cap
            assert 429 in statuses  # lockout trips over the cap
            # shared: the bearer endpoint is locked for the same identity
            assert (
                await client.post("/token", data={"username": "carol", "password": "pw123456"})
            ).status_code == 429
    finally:
        await auth.shutdown()


async def test_device_management_lifecycle(app_ctx: Any) -> None:
    auth, client, maker, channel = app_ctx
    await _register(client, email="d@x.com", username="dave")

    a = await client.post("/login", data={"username": "dave", "password": "pw123456"})
    csrf_a = a.json()["csrf_token"]
    # a second device: reuse the same ASGI transport (same app), fresh cookie jar
    async with httpx.AsyncClient(transport=client._transport, base_url="http://test") as b:
        await b.post("/login", data={"username": "dave", "password": "pw123456"})

        sessions = await client.get("/sessions")
        assert sessions.status_code == 200
        assert len(sessions.json()) == 2  # both devices listed

        out = await client.post("/logout-all?keep_current=true", headers={"X-CSRF-Token": csrf_a})
        assert out.status_code == 200 and out.json()["revoked"] == 1
        assert (await client.get("/me")).status_code == 200  # caller kept
        assert (await b.get("/me")).status_code == 401  # other device gone


async def test_recovery_verification_journey(app_ctx: Any) -> None:
    auth, client, maker, channel = app_ctx
    await _register(client, email="e@x.com", username="erin")

    # registration already enrolled a verify; confirm it and check the flag flips
    verify = next(i for i in channel.intents if i.kind in ("verify_email", "verify_recovery"))
    confirmed = await client.post("/email/verify-confirm", json={"token": verify.token})
    assert confirmed.status_code == 200
    async with maker() as db:
        user = await auth.repo.get_by_email(db, "e@x.com")
        assert auth.repo.recovery_verified(user) is True


async def test_registration_is_hardened(app_ctx: Any) -> None:
    auth, client, maker, channel = app_ctx
    # privileged column can't be set at signup (role is not in register_extra_fields)
    await _register(client, email="f@x.com", username="frank", role="admin")
    async with maker() as db:
        user = await auth.repo.get_by_email(db, "f@x.com")
        assert auth.repo.is_superuser(user) is False  # privileged flag gated
        assert user.role == "user"  # privileged app column dropped, not "admin"

    # a duplicate registration is non-enumerable: same 202 + detail, no leak
    dup = await _register(client, email="f@x.com", username="frank2")
    assert dup.status_code == 202
