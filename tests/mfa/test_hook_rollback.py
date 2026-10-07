"""A hook that writes through ``db`` and rolls back, or fails, doesn't break the request it ran in.

The hooks guide tells a hook to roll back its own failed work. A rollback expires every
row the session holds, the user crudauth goes on reading included, and reading an
expired row outside SQLAlchemy's greenlet raised ``MissingGreenlet``: a 500 for a
registration or a login that had already succeeded. A hook that raised after a failed
flush left the session refusing every later statement until a rollback.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

from crudauth import AuthHooks, MfaConfig, OAuthCredentials
from crudauth.oauth import AbstractOAuthProvider, OAuthProviderFactory, OAuthUserInfo

from .conftest import MFA_KEY, PASSWORD, MfaUser, client, enroll, register_and_login


async def _rolls_back(*args: Any, db: Any, **kwargs: Any) -> None:
    await db.rollback()


async def test_a_register_hook_that_rolls_back_still_answers_the_registration(build) -> None:
    auth, app = build(hooks=AuthHooks(on_after_register=_rolls_back))
    await auth.initialize()

    async with client(app) as browser:
        response = await browser.post(
            "/register", json={"email": "a@x.com", "username": "alice", "password": PASSWORD}
        )

    assert response.status_code == 200, response.text
    assert response.json()["username"] == "alice"


class _Provider(AbstractOAuthProvider):
    def __init__(self, client_id, client_secret, redirect_uri, scopes=None):
        super().__init__(
            client_id,
            client_secret,
            redirect_uri,
            scopes=["email"],
            authorize_endpoint="https://idp.example/authorize",
            token_endpoint="https://idp.example/token",
            userinfo_endpoint="https://idp.example/userinfo",
            provider_name="stub",
        )

    async def exchange_code(self, code, code_verifier=None, headers=None):
        return {"access_token": "tok"}

    async def get_user_info(self, access_token):
        return {"id": "idp-1", "email": "new@x.com"}

    async def process_user_info(self, user_info) -> OAuthUserInfo:
        return OAuthUserInfo(
            provider="stub",
            provider_user_id=user_info["id"],
            email=user_info["email"],
            email_verified=True,
        )


async def test_a_hook_whose_flush_failed_does_not_break_the_writes_after_it(
    build, monkeypatch
) -> None:
    """A new OAuth account that must enroll: after ``on_after_register`` the challenge stores a
    pending secret through the same ``db``. A hook whose flush failed left that session raising
    ``PendingRollbackError`` until a rollback, so the sign-in failed."""
    monkeypatch.setitem(OAuthProviderFactory._providers, "stub", _Provider)

    async def fails_to_flush(user: dict, *, db: Any, context: Any) -> None:
        db.add(MfaUser(email=None, username=None, hashed_password=None))
        await db.flush()

    auth, app = build(
        mfa=MfaConfig(issuer="Acme", encryption_key=MFA_KEY, required=True, oauth=True),
        oauth={"stub": OAuthCredentials(client_id="id", client_secret="s")},
        redirect_base_url="http://test",
        hooks=AuthHooks(on_after_register=fails_to_flush),
    )
    await auth.initialize()

    async with client(app) as browser:
        authorize = await browser.get("/oauth/stub/authorize")
        state = parse_qs(urlparse(authorize.headers["location"]).query)["state"][0]
        callback = await browser.get(f"/oauth/stub/callback?code=abc&state={state}")

    assert callback.status_code == 307
    assert "#mfa_challenge=" in callback.headers["location"]


async def test_a_recovery_code_hook_that_rolls_back_still_finishes_the_login(build) -> None:
    auth, app = build(hooks=AuthHooks(on_after_recovery_code_used=_rolls_back))
    await auth.initialize()
    async with client(app) as enrolling:
        csrf = (await register_and_login(enrolling)).json()["csrf_token"]
        _, recovery_codes = await enroll(enrolling, csrf)

    async with client(app) as browser:
        challenge = (
            await browser.post("/login", data={"username": "alice", "password": PASSWORD})
        ).json()["challenge"]
        verified = await browser.post(
            "/mfa/verify", json={"challenge": challenge, "code": recovery_codes[0]}
        )
        me = await browser.get("/me")

    assert verified.status_code == 200, verified.text
    assert me.status_code == 200
