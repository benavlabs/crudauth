"""MFA over HTTP: enrollment, login challenges on both transports, recovery codes, disabling."""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import parse_qs, urlparse

import fakeredis.aioredis
import pytest
from cryptography.fernet import Fernet
from fastapi import Depends, Request

from crudauth import (
    AuthHooks,
    BearerTransport,
    CookieConfig,
    CRUDAuth,
    EmailConfig,
    EmailSender,
    MfaConfig,
    OAuthCredentials,
    Principal,
    SessionTransport,
    SudoConfig,
)
from crudauth.exceptions import BadRequestException
from crudauth.mfa.constants import MFA_FIELDS
from crudauth.mfa.recovery import hash_recovery_codes
from crudauth.oauth import AbstractOAuthProvider, OAuthProviderFactory, OAuthUserInfo
from crudauth.ratelimit import LockoutConfig
from crudauth.storage.backends.memory import MemorySessionStorage
from tests.conftest import mounted_paths

from .conftest import (
    MFA_KEY,
    PASSWORD,
    SECRET,
    MfaUser,
    client,
    code_for,
    enroll,
    register_and_login,
)


async def _login(browser, username: str = "alice", password: str = PASSWORD):
    return await browser.post("/login", data={"username": username, "password": password})


async def _enrolled_app(build, **options: Any):
    auth, app = build(**options)
    await auth.initialize()
    async with client(app) as enrolling:
        csrf = (await register_and_login(enrolling)).json()["csrf_token"]
        secret, recovery_codes = await enroll(enrolling, csrf)
    return auth, app, client(app), secret, recovery_codes


async def test_enrollment_needs_the_password_and_returns_recovery_codes(build) -> None:
    auth, app = build()
    await auth.initialize()
    async with client(app) as browser:
        csrf = (await register_and_login(browser)).json()["csrf_token"]
        headers = {"X-CSRF-Token": csrf}
        missing = await browser.post("/mfa/totp/setup", json={}, headers=headers)
        wrong = await browser.post("/mfa/totp/setup", json={"password": "nope"}, headers=headers)
        setup = await browser.post("/mfa/totp/setup", json={"password": PASSWORD}, headers=headers)
        secret = setup.json()["secret"]
        bad_confirm = await browser.post(
            "/mfa/totp/confirm", json={"code": code_for(secret, 5)}, headers=headers
        )
        before = (await browser.get("/mfa")).json()
        confirm = await browser.post(
            "/mfa/totp/confirm", json={"code": code_for(secret)}, headers=headers
        )
        again = await browser.post("/mfa/totp/setup", json={"password": PASSWORD}, headers=headers)
        after = (await browser.get("/mfa")).json()
    await auth.shutdown()

    assert (missing.status_code, wrong.status_code, bad_confirm.status_code) == (401, 401, 401)
    assert setup.json()["otpauth_uri"].startswith("otpauth://totp/Acme%3Aalice%40x.com?")
    assert before == {"enabled": False, "required": False, "recovery_codes_remaining": 0}
    assert confirm.status_code == 200 and len(confirm.json()["recovery_codes"]) == 10
    assert after == {"enabled": True, "required": False, "recovery_codes_remaining": 10}
    assert again.status_code == 400


async def test_a_session_login_needs_the_code(build) -> None:
    logins: list[str] = []
    hooks = AuthHooks(on_after_login=lambda user, **kwargs: logins.append(user["username"]))
    auth, app, browser, secret, _ = await _enrolled_app(build, hooks=hooks)
    logins.clear()
    async with browser:
        challenge = await _login(browser)
        body = challenge.json()
        no_session = await browser.get("/me")
        wrong = await browser.post(
            "/mfa/verify", json={"challenge": body["challenge"], "code": code_for(secret, 5)}
        )
        hooks_before_code = list(logins)
        verified = await browser.post(
            "/mfa/verify", json={"challenge": body["challenge"], "code": code_for(secret)}
        )
        me = await browser.get("/me")
        reused = await browser.post(
            "/mfa/verify", json={"challenge": body["challenge"], "code": code_for(secret)}
        )
    await auth.shutdown()

    assert challenge.status_code == 200
    assert body["mfa_required"] is True and "setup" not in body
    assert "set-cookie" not in challenge.headers
    assert no_session.status_code == 401
    assert wrong.status_code == 401
    assert hooks_before_code == []
    assert verified.status_code == 200 and verified.json()["csrf_token"]
    assert me.status_code == 200
    assert logins == ["alice"]
    assert reused.status_code == 400


async def test_a_token_login_needs_the_code(build) -> None:
    transports = [
        SessionTransport(cookies=CookieConfig(secure=False)),
        BearerTransport(refresh="body"),
    ]
    auth, app, browser, secret, _ = await _enrolled_app(build, transports=transports)
    async with browser:
        challenge = await browser.post("/token", data={"username": "alice", "password": PASSWORD})
        verified = await browser.post(
            "/mfa/verify",
            json={"challenge": challenge.json()["challenge"], "code": code_for(secret)},
        )
        me = await browser.get(
            "/me", headers={"Authorization": f"Bearer {verified.json()['access_token']}"}
        )
    await auth.shutdown()

    assert "access_token" not in challenge.json()
    assert verified.json()["refresh_token"]
    assert me.json()["via"] == "bearer"


async def test_a_code_is_accepted_once(build) -> None:
    auth, app, browser, secret, _ = await _enrolled_app(build)
    async with browser:
        code = code_for(secret, 1)
        first = await _login(browser)
        ok = await browser.post(
            "/mfa/verify", json={"challenge": first.json()["challenge"], "code": code}
        )
        browser.cookies.clear()
        second = await _login(browser)
        replay = await browser.post(
            "/mfa/verify", json={"challenge": second.json()["challenge"], "code": code}
        )
        older = await browser.post(
            "/mfa/verify",
            json={"challenge": second.json()["challenge"], "code": code_for(secret)},
        )
    await auth.shutdown()

    assert ok.status_code == 200
    assert (replay.status_code, older.status_code) == (401, 401)


async def test_concurrent_requests_with_one_code_let_only_one_through(build) -> None:
    auth, app, browser, secret, _ = await _enrolled_app(build)
    async with browser, client(app) as other:
        challenges = [(await _login(browser)).json()["challenge"] for _ in range(2)]
        code = code_for(secret)
        results = await asyncio.gather(
            browser.post("/mfa/verify", json={"challenge": challenges[0], "code": code}),
            other.post("/mfa/verify", json={"challenge": challenges[1], "code": code}),
        )
    await auth.shutdown()

    assert sorted(result.status_code for result in results) == [200, 401]


async def test_codes_outside_the_window_and_full_width_digits_are_rejected(build) -> None:
    auth, app, browser, secret, _ = await _enrolled_app(build)
    async with browser:
        token = (await _login(browser)).json()["challenge"]
        code = code_for(secret)
        full_width = "".join(chr(ord(digit) + 0xFEE0) for digit in code)
        responses = [
            await browser.post("/mfa/verify", json={"challenge": token, "code": attempt})
            for attempt in (code_for(secret, -3), code_for(secret, 3), full_width)
        ]
        spaced = await browser.post(
            "/mfa/verify", json={"challenge": token, "code": f"{code[:3]} {code[3:]}"}
        )
    await auth.shutdown()

    assert [response.status_code for response in responses] == [401, 401, 401]
    assert spaced.status_code == 200


async def test_a_challenge_dies_after_too_many_wrong_codes(build) -> None:
    config = MfaConfig(issuer="Acme", encryption_key=MFA_KEY, max_code_attempts=3)
    auth, app, browser, secret, _ = await _enrolled_app(
        build, mfa=config, lockout=LockoutConfig(max_attempts=50)
    )
    async with browser:
        token = (await _login(browser)).json()["challenge"]
        wrong = [
            (
                await browser.post(
                    "/mfa/verify", json={"challenge": token, "code": code_for(secret, 9)}
                )
            ).status_code
            for _ in range(3)
        ]
        right = await browser.post(
            "/mfa/verify", json={"challenge": token, "code": code_for(secret)}
        )
    await auth.shutdown()

    assert wrong == [401, 401, 401]
    assert right.status_code == 400


async def test_a_challenge_expires(build, monkeypatch) -> None:
    auth, app, browser, secret, _ = await _enrolled_app(build)
    async with browser:
        token = (await _login(browser)).json()["challenge"]
        store = auth.mfa.challenges
        assert isinstance(store, MemorySessionStorage)
        for key in list(store.expiry):
            store.expiry[key] = store.expiry[key].replace(year=2000)
        expired = await browser.post(
            "/mfa/verify", json={"challenge": token, "code": code_for(secret)}
        )
    await auth.shutdown()

    assert expired.status_code == 400


async def test_a_correct_password_does_not_reset_the_lockout(build) -> None:
    auth, app, browser, secret, _ = await _enrolled_app(
        build, lockout=LockoutConfig(max_attempts=4)
    )
    async with browser:
        for _ in range(2):
            await _login(browser, password="wrong")
        challenged = await _login(browser)
        failures = [(await _login(browser, password="wrong")).status_code for _ in range(2)]
        locked = await _login(browser)
    await auth.shutdown()

    assert challenged.json()["mfa_required"] is True
    assert (failures, locked.status_code) == ([401, 401], 429)


async def test_a_correct_code_resets_the_lockout(build) -> None:
    auth, app, browser, secret, _ = await _enrolled_app(
        build, lockout=LockoutConfig(max_attempts=4)
    )
    async with browser:
        for _ in range(2):
            await _login(browser, password="wrong")
        token = (await _login(browser)).json()["challenge"]
        await browser.post("/mfa/verify", json={"challenge": token, "code": code_for(secret)})
        browser.cookies.clear()
        after = [(await _login(browser, password="wrong")).status_code for _ in range(4)]
    await auth.shutdown()

    assert after == [401, 401, 401, 401]


async def test_a_required_account_enrolls_during_login(build) -> None:
    enabled: list[str] = []
    config = MfaConfig(issuer="Acme", encryption_key=MFA_KEY, required=True)
    hooks = AuthHooks(on_after_mfa_enabled=lambda user, **kwargs: enabled.append(user["username"]))
    auth, app = build(mfa=config, hooks=hooks)
    await auth.initialize()
    async with client(app) as browser:
        first = await register_and_login(browser)
        interrupted = await _login(browser)
        described = await browser.post(
            "/mfa/challenge", json={"challenge": interrupted.json()["challenge"]}
        )
        secret = first.json()["setup"]["secret"]
        verified = await browser.post(
            "/mfa/verify",
            json={"challenge": interrupted.json()["challenge"], "code": code_for(secret)},
        )
        me = await browser.get("/me")
        status = (await browser.get("/mfa")).json()
        disable = await browser.post(
            "/mfa/totp/disable",
            json={"code": code_for(secret, 1)},
            headers={"X-CSRF-Token": verified.json()["csrf_token"]},
        )
    await auth.shutdown()

    assert first.json()["mfa_required"] is True
    assert interrupted.json()["setup"]["secret"] == secret
    assert described.json()["setup"]["secret"] == secret
    assert verified.status_code == 200 and len(verified.json()["recovery_codes"]) == 10
    assert me.status_code == 200
    assert status == {"enabled": True, "required": True, "recovery_codes_remaining": 10}
    assert enabled == ["alice"]
    assert disable.status_code == 403


async def test_a_predicate_decides_who_must_enroll(build) -> None:
    config = MfaConfig(
        issuer="Acme", encryption_key=MFA_KEY, required=lambda user: user.username == "admin"
    )
    auth, app = build(mfa=config)
    await auth.initialize()
    async with client(app) as admin, client(app) as member:
        admin_login = await register_and_login(admin, "admin")
        member_login = await register_and_login(member, "member")
    await auth.shutdown()

    assert admin_login.json()["mfa_required"] is True
    assert "csrf_token" in member_login.json()


async def test_a_recovery_code_works_once(build) -> None:
    used: list[str] = []
    hooks = AuthHooks(
        on_after_recovery_code_used=lambda user, **kwargs: used.append(user["username"])
    )
    auth, app, browser, secret, recovery_codes = await _enrolled_app(build, hooks=hooks)
    async with browser:
        token = (await _login(browser)).json()["challenge"]
        first = await browser.post(
            "/mfa/verify", json={"challenge": token, "code": recovery_codes[0].upper()}
        )
        status = (await browser.get("/mfa")).json()
        browser.cookies.clear()
        token = (await _login(browser)).json()["challenge"]
        again = await browser.post(
            "/mfa/verify", json={"challenge": token, "code": recovery_codes[0]}
        )
    await auth.shutdown()

    assert first.status_code == 200
    assert status["recovery_codes_remaining"] == 9
    assert again.status_code == 401
    assert used == ["alice"]


async def test_regenerating_recovery_codes_replaces_the_old_ones(build) -> None:
    auth, app, browser, secret, recovery_codes = await _enrolled_app(build)
    async with browser:
        token = (await _login(browser)).json()["challenge"]
        csrf = (
            await browser.post("/mfa/verify", json={"challenge": token, "code": code_for(secret)})
        ).json()["csrf_token"]
        headers = {"X-CSRF-Token": csrf}
        refused = await browser.post(
            "/mfa/recovery-codes/regenerate", json={"code": "000000"}, headers=headers
        )
        regenerated = await browser.post(
            "/mfa/recovery-codes/regenerate", json={"code": code_for(secret, 1)}, headers=headers
        )
        browser.cookies.clear()
        token = (await _login(browser)).json()["challenge"]
        old = await browser.post(
            "/mfa/verify", json={"challenge": token, "code": recovery_codes[1]}
        )
        new = await browser.post(
            "/mfa/verify",
            json={"challenge": token, "code": regenerated.json()["recovery_codes"][0]},
        )
    await auth.shutdown()

    assert refused.status_code == 401
    assert regenerated.status_code == 200
    assert set(regenerated.json()["recovery_codes"]).isdisjoint(recovery_codes)
    assert (old.status_code, new.status_code) == (401, 200)


async def test_disabling_needs_a_code_and_turns_the_challenge_off(build) -> None:
    disabled: list[str] = []
    hooks = AuthHooks(
        on_after_mfa_disabled=lambda user, **kwargs: disabled.append(user["username"])
    )
    auth, app, browser, secret, recovery_codes = await _enrolled_app(build, hooks=hooks)
    async with browser:
        token = (await _login(browser)).json()["challenge"]
        csrf = (
            await browser.post("/mfa/verify", json={"challenge": token, "code": recovery_codes[0]})
        ).json()["csrf_token"]
        headers = {"X-CSRF-Token": csrf}
        refused = await browser.post("/mfa/totp/disable", json={"code": "123456"}, headers=headers)
        done = await browser.post(
            "/mfa/totp/disable", json={"code": recovery_codes[1]}, headers=headers
        )
        browser.cookies.clear()
        plain = await _login(browser)
    await auth.shutdown()

    assert (refused.status_code, done.status_code) == (401, 200)
    assert "csrf_token" in plain.json()
    assert disabled == ["alice"]


async def test_a_tampered_secret_fails_closed(build, mfa_sessionmaker) -> None:
    auth, app, browser, secret, recovery_codes = await _enrolled_app(build)
    async with mfa_sessionmaker() as db:
        user = await auth.repo.get_by_username(db, "alice")
        stored = auth.repo.get(user, "totp_secret_encrypted")
        await auth.repo.update(db, user, {"totp_secret_encrypted": stored[:-6] + "AAAAAA"})
    async with browser:
        token = (await _login(browser)).json()["challenge"]
        totp = await browser.post(
            "/mfa/verify", json={"challenge": token, "code": code_for(secret)}
        )
        recovery = await browser.post(
            "/mfa/verify", json={"challenge": token, "code": recovery_codes[0]}
        )
    await auth.shutdown()

    assert totp.status_code == 401
    assert recovery.status_code == 200


async def test_secrets_are_encrypted_at_rest_and_hidden_from_hooks(build, mfa_sessionmaker) -> None:
    auth, app, browser, secret, recovery_codes = await _enrolled_app(build)
    await browser.aclose()
    async with mfa_sessionmaker() as db:
        user = await auth.repo.get_by_username(db, "alice")
    await auth.shutdown()

    stored = auth.repo.get(user, "totp_secret_encrypted")
    assert secret not in stored
    assert Fernet(MFA_KEY.encode()).decrypt(stored.encode()).decode() == secret
    assert not any(code in auth.repo.get(user, "mfa_recovery_codes") for code in recovery_codes)
    assert {"totp_secret_encrypted", "mfa_recovery_codes"}.isdisjoint(auth.repo.to_dict(user))


async def test_a_cross_site_verify_for_a_session_login_is_refused(build) -> None:
    auth, app, browser, secret, _ = await _enrolled_app(build)
    async with browser:
        token = (await _login(browser)).json()["challenge"]
        response = await browser.post(
            "/mfa/verify",
            json={"challenge": token, "code": code_for(secret)},
            headers={"Sec-Fetch-Site": "cross-site"},
        )
    await auth.shutdown()

    assert response.status_code == 403


async def test_challenges_work_on_redis(build) -> None:
    auth, app, browser, secret, _ = await _enrolled_app(
        build, redis_client=fakeredis.aioredis.FakeRedis()
    )
    async with browser:
        token = (await _login(browser)).json()["challenge"]
        verified = await browser.post(
            "/mfa/verify", json={"challenge": token, "code": code_for(secret)}
        )
    await auth.shutdown()

    assert verified.status_code == 200


def test_mfa_needs_its_columns(get_session, UserModel) -> None:
    with pytest.raises(ValueError, match="make_auth_identity\\(mfa=True\\)"):
        CRUDAuth(
            session=get_session,
            user_model=UserModel,
            SECRET_KEY=SECRET,
            mfa=MfaConfig(issuer="Acme", encryption_key=MFA_KEY),
        )


def test_the_encryption_key_must_differ_from_the_secret_key(mfa_session) -> None:
    key = Fernet.generate_key().decode()
    with pytest.raises(ValueError, match="differ from SECRET_KEY"):
        CRUDAuth(
            session=mfa_session,
            user_model=MfaUser,
            SECRET_KEY=key,
            mfa=MfaConfig(issuer="Acme", encryption_key=[Fernet.generate_key().decode(), key]),
        )


@pytest.mark.parametrize(
    "options",
    [{"issuer": ""}, {"encryption_key": ""}, {"max_code_attempts": 0}, {"encryption_key": "bad"}],
)
def test_an_invalid_config_fails_at_construction(mfa_session, options: dict[str, Any]) -> None:
    config = {"issuer": "Acme", "encryption_key": MFA_KEY, **options}
    with pytest.raises(ValueError):
        CRUDAuth(
            session=mfa_session,
            user_model=MfaUser,
            SECRET_KEY=SECRET,
            mfa=MfaConfig(**config),
        )


def test_without_mfa_nothing_is_mounted(get_session, UserModel) -> None:
    auth = CRUDAuth(session=get_session, user_model=UserModel, SECRET_KEY=SECRET)
    paths = mounted_paths(auth.router)

    assert auth.mfa is None
    assert not any(path.startswith("/mfa") for path in paths)


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
        return {"id": "idp-1", "email": "alice@x.com"}

    async def process_user_info(self, user_info) -> OAuthUserInfo:
        return OAuthUserInfo(
            provider="stub",
            provider_user_id=user_info["id"],
            email=user_info["email"],
            email_verified=True,
        )


@pytest.mark.parametrize(
    ("oauth_mfa", "mode"), [(True, "redirect"), (True, "json"), (False, "redirect")]
)
async def test_oauth_logins_are_challenged_only_when_configured(
    build, monkeypatch, mfa_sessionmaker, oauth_mfa: bool, mode: str
) -> None:
    monkeypatch.setitem(OAuthProviderFactory._providers, "stub", _Provider)
    config = MfaConfig(issuer="Acme", encryption_key=MFA_KEY, oauth=oauth_mfa)
    auth, app, browser, secret, _ = await _enrolled_app(
        build,
        mfa=config,
        oauth={"stub": OAuthCredentials(client_id="id", client_secret="s")},
        redirect_base_url="http://test",
        oauth_response_mode=mode,
    )
    async with mfa_sessionmaker() as db:
        user = await auth.repo.get_by_username(db, "alice")
        await auth.repo.update(db, user, {"email_verified": True})
    async with browser:
        authorize = await browser.get("/oauth/stub/authorize?redirect_to=/dashboard")
        url = authorize.json()["url"] if mode == "json" else authorize.headers["location"]
        state = parse_qs(urlparse(url).query)["state"][0]
        callback = await browser.get(f"/oauth/stub/callback?code=abc&state={state}")
        if oauth_mfa:
            token = (
                callback.json()["challenge"]
                if mode == "json"
                else callback.headers["location"].split("#mfa_challenge=")[1]
            )
            assert (await browser.get("/me")).status_code == 401
            verified = await browser.post(
                "/mfa/verify", json={"challenge": token, "code": code_for(secret)}
            )
            assert verified.json()["redirect_to"] == "/dashboard"
        me = await browser.get("/me")
    await auth.shutdown()

    assert me.status_code == 200


async def test_sudo_accepts_an_authenticator_code_once(build, mfa_sessionmaker) -> None:
    auth, app, browser, secret, _ = await _enrolled_app(build, sudo=SudoConfig())
    sudo = auth.sudo
    assert sudo is not None

    @app.post("/sudo")
    async def elevate(
        body: dict,
        request: Request,
        principal: Principal = Depends(auth.current_user()),
        db: Any = Depends(auth.session),
    ):
        await sudo.elevate(principal, code=body["code"], db=db, request=request)
        return {"elevated": await sudo.is_elevated(principal)}

    async with browser:
        token = (await _login(browser)).json()["challenge"]
        csrf = (
            await browser.post("/mfa/verify", json={"challenge": token, "code": code_for(secret)})
        ).json()["csrf_token"]
        headers = {"X-CSRF-Token": csrf}
        elevated = await browser.post("/sudo", json={"code": code_for(secret, 1)}, headers=headers)
        replayed = await browser.post("/sudo", json={"code": code_for(secret, 1)}, headers=headers)
    await auth.shutdown()

    assert elevated.json() == {"elevated": True}
    assert replayed.status_code == 401


async def test_a_time_step_is_claimed_by_one_of_two_stale_rows(build, mfa_sessionmaker) -> None:
    auth, app, browser, secret, _ = await _enrolled_app(build)
    await browser.aclose()
    async with mfa_sessionmaker() as first_db, mfa_sessionmaker() as second_db:
        first = await auth.repo.get_by_username(first_db, "alice")
        second = await auth.repo.get_by_username(second_db, "alice")
        step = auth.repo.get(first, "totp_last_step") + 1
        claims = [
            await auth.repo.claim_totp_step(first_db, first, step),
            await auth.repo.claim_totp_step(second_db, second, step),
        ]
    await auth.shutdown()

    assert claims == [True, False]


async def test_wrong_codes_count_against_the_login_lockout(build) -> None:
    config = MfaConfig(issuer="Acme", encryption_key=MFA_KEY, max_code_attempts=10)
    auth, app, browser, secret, _ = await _enrolled_app(
        build, mfa=config, lockout=LockoutConfig(max_attempts=3)
    )
    async with browser:
        token = (await _login(browser)).json()["challenge"]
        statuses = [
            (
                await browser.post(
                    "/mfa/verify", json={"challenge": token, "code": code_for(secret, 9)}
                )
            ).status_code
            for _ in range(4)
        ]
    await auth.shutdown()

    assert statuses == [401, 401, 401, 429]


async def test_concurrent_wrong_codes_share_the_attempt_cap(build, monkeypatch) -> None:
    config = MfaConfig(issuer="Acme", encryption_key=MFA_KEY, max_code_attempts=3)
    auth, app, browser, secret, _ = await _enrolled_app(
        build, mfa=config, lockout=LockoutConfig(max_attempts=50)
    )
    service = auth.mfa
    assert service is not None
    checked: list[str] = []
    verify_code = service.verify_code

    async def counting_verify(*args: Any, **kwargs: Any) -> bool:
        checked.append("code")
        return await verify_code(*args, **kwargs)

    monkeypatch.setattr(service, "verify_code", counting_verify)
    async with browser:
        token = (await _login(browser)).json()["challenge"]
        await asyncio.gather(
            *(
                browser.post("/mfa/verify", json={"challenge": token, "code": code_for(secret, 9)})
                for _ in range(8)
            )
        )
    await auth.shutdown()

    assert len(checked) <= 3


class _ResetSender(EmailSender):
    def __init__(self) -> None:
        self.tokens: dict[str, str] = {}

    async def send(self, *, to, subject, body, kind, context):
        self.tokens[kind] = body.split("token=")[-1]


async def test_a_password_reset_discards_a_pending_enrollment_secret(build) -> None:
    sender = _ResetSender()
    config = MfaConfig(issuer="Acme", encryption_key=MFA_KEY, required=True)
    auth, app = build(mfa=config, email=EmailConfig(sender=sender, frontend_url="https://app"))
    await auth.initialize()
    async with client(app) as intruder, client(app) as owner:
        seen_by_intruder = (await register_and_login(intruder)).json()["setup"]["secret"]
        await owner.post("/password/reset-request", json={"email": "alice@x.com"})
        await owner.post(
            "/password/reset-confirm",
            json={"token": sender.tokens["reset_password"], "new_password": "owner-new-pw-1"},
        )
        owner_login = await owner.post(
            "/login", data={"username": "alice", "password": "owner-new-pw-1"}
        )
        stale = await intruder.post(
            "/mfa/challenge", json={"challenge": owner_login.json()["challenge"]}
        )
    await auth.shutdown()

    assert owner_login.json()["setup"]["secret"] != seen_by_intruder
    assert stale.json()["setup"]["secret"] == owner_login.json()["setup"]["secret"]


async def test_an_oauth_claim_removes_mfa_set_up_by_whoever_registered_the_account(
    build, monkeypatch, mfa_sessionmaker
) -> None:
    monkeypatch.setitem(OAuthProviderFactory._providers, "stub", _Provider)
    auth, app, browser, secret, _ = await _enrolled_app(
        build,
        oauth={"stub": OAuthCredentials(client_id="id", client_secret="s")},
        redirect_base_url="http://test",
    )
    async with browser:
        authorize = await browser.get("/oauth/stub/authorize")
        state = parse_qs(urlparse(authorize.headers["location"]).query)["state"][0]
        await browser.get(f"/oauth/stub/callback?code=abc&state={state}")
    async with mfa_sessionmaker() as db:
        user = await auth.repo.get_by_username(db, "alice")
    await auth.shutdown()

    assert auth.mfa is not None and not auth.mfa.is_enrolled(user)
    assert all(auth.repo.get(user, field) is None for field in MFA_FIELDS)


async def test_redis_challenges_leave_no_per_user_index(build) -> None:
    redis = fakeredis.aioredis.FakeRedis()
    auth, app, browser, secret, _ = await _enrolled_app(build, redis_client=redis)
    async with browser:
        token = (await _login(browser)).json()["challenge"]
        during = await redis.keys("mfa_challenge*")
        await browser.post("/mfa/verify", json={"challenge": token, "code": code_for(secret)})
        after = await redis.keys("mfa_challenge*")
    await auth.shutdown()

    assert len(during) == 1
    assert after == []


async def test_a_refused_cross_site_verify_does_not_use_an_attempt(build) -> None:
    config = MfaConfig(issuer="Acme", encryption_key=MFA_KEY, max_code_attempts=1)
    auth, app, browser, secret, _ = await _enrolled_app(build, mfa=config)
    async with browser:
        token = (await _login(browser)).json()["challenge"]
        body = {"challenge": token, "code": code_for(secret)}
        refused = await browser.post(
            "/mfa/verify", json=body, headers={"Sec-Fetch-Site": "cross-site"}
        )
        verified = await browser.post("/mfa/verify", json=body)
    await auth.shutdown()

    assert (refused.status_code, verified.status_code) == (403, 200)


def test_a_bytes_encryption_key_is_accepted_and_still_compared_to_the_secret_key(
    mfa_session,
) -> None:
    key = Fernet.generate_key()
    auth = CRUDAuth(
        session=mfa_session,
        user_model=MfaUser,
        SECRET_KEY=SECRET,
        mfa=MfaConfig(issuer="Acme", encryption_key=key),
    )

    assert auth.mfa is not None
    with pytest.raises(ValueError, match="differ from SECRET_KEY"):
        CRUDAuth(
            session=mfa_session,
            user_model=MfaUser,
            SECRET_KEY=key.decode(),
            mfa=MfaConfig(issuer="Acme", encryption_key=key),
        )


async def test_a_password_reset_voids_an_outstanding_challenge(build, mfa_sessionmaker) -> None:
    auth, app, browser, secret, _ = await _enrolled_app(build)
    async with browser:
        token = (await _login(browser)).json()["challenge"]
        async with mfa_sessionmaker() as db:
            user = await auth.repo.get_by_username(db, "alice")
            await auth.repo.increment_token_version(db, user)
        verified = await browser.post(
            "/mfa/verify", json={"challenge": token, "code": code_for(secret)}
        )
    await auth.shutdown()

    assert verified.status_code == 400


async def test_every_code_attempt_is_usable_under_the_default_lockout(build) -> None:
    auth, app, browser, secret, _ = await _enrolled_app(build)
    async with browser:
        token = (await _login(browser)).json()["challenge"]
        wrong = [
            (
                await browser.post(
                    "/mfa/verify", json={"challenge": token, "code": code_for(secret, 9)}
                )
            ).status_code
            for _ in range(4)
        ]
        right = await browser.post(
            "/mfa/verify", json={"challenge": token, "code": code_for(secret)}
        )
    await auth.shutdown()

    assert (wrong, right.status_code) == ([401, 401, 401, 401], 200)


async def test_only_one_of_two_racing_confirmations_hands_out_recovery_codes(
    build, mfa_sessionmaker
) -> None:
    auth, app = build()
    service = auth.mfa
    assert service is not None
    await auth.initialize()
    async with client(app) as browser:
        csrf = (await register_and_login(browser)).json()["csrf_token"]
        setup = await browser.post(
            "/mfa/totp/setup", json={"password": PASSWORD}, headers={"X-CSRF-Token": csrf}
        )
    secret = setup.json()["secret"]
    async with mfa_sessionmaker() as first_db, mfa_sessionmaker() as second_db:
        first = await auth.repo.get_by_username(first_db, "alice")
        second = await auth.repo.get_by_username(second_db, "alice")
        issued = await service.confirm_setup(first_db, first, code_for(secret, -1))
        with pytest.raises(BadRequestException):
            await service.confirm_setup(second_db, second, code_for(secret))
    async with mfa_sessionmaker() as db:
        stored = auth.repo.get(await auth.repo.get_by_username(db, "alice"), "mfa_recovery_codes")
    await auth.shutdown()

    assert stored == hash_recovery_codes(issued)


@pytest.mark.parametrize("cross_site", [False, True])
async def test_a_token_login_with_a_refresh_cookie_verifies_like_a_session_login(
    build, cross_site: bool
) -> None:
    transports = [
        SessionTransport(cookies=CookieConfig(secure=False)),
        BearerTransport(refresh="cookie", cookies=CookieConfig(secure=False)),
    ]
    auth, app, browser, secret, _ = await _enrolled_app(build, transports=transports)
    async with browser:
        token = (
            await browser.post("/token", data={"username": "alice", "password": PASSWORD})
        ).json()["challenge"]
        headers = {"Sec-Fetch-Site": "cross-site"} if cross_site else {}
        verified = await browser.post(
            "/mfa/verify", json={"challenge": token, "code": code_for(secret)}, headers=headers
        )
    await auth.shutdown()

    if cross_site:
        assert verified.status_code == 403
    else:
        assert verified.status_code == 200 and "refresh_token" in browser.cookies


def test_required_mfa_with_oauth_skipped_warns_at_startup(mfa_session, caplog, monkeypatch) -> None:
    monkeypatch.setitem(OAuthProviderFactory._providers, "stub", _Provider)
    with caplog.at_level(logging.WARNING, logger="crudauth"):
        CRUDAuth(
            session=mfa_session,
            user_model=MfaUser,
            SECRET_KEY=SECRET,
            transports=[SessionTransport()],
            oauth={"stub": OAuthCredentials(client_id="id", client_secret="s")},
            redirect_base_url="http://test",
            mfa=MfaConfig(issuer="Acme", encryption_key=MFA_KEY, required=True),
            warn_on_memory_backend=False,
        )
        quiet = len(caplog.records)
        CRUDAuth(
            session=mfa_session,
            user_model=MfaUser,
            SECRET_KEY=SECRET,
            transports=[SessionTransport()],
            oauth={"stub": OAuthCredentials(client_id="id", client_secret="s")},
            redirect_base_url="http://test",
            mfa=MfaConfig(issuer="Acme", encryption_key=MFA_KEY, required=True, oauth=True),
            warn_on_memory_backend=False,
        )

    assert quiet == 1 and "sign in without a code" in caplog.records[0].getMessage()
    assert len(caplog.records) == 1
