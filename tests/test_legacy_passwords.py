"""Signing in with a password hash another system wrote, and the hooks a refused login runs."""

from __future__ import annotations

import base64
import hashlib
from typing import Any

import bcrypt
import httpx
import pytest
from fastapi import FastAPI

from crudauth import AuthHooks, CookieConfig, CRUDAuth, SessionTransport
from crudauth.repository import UserRepository
from crudauth.utils import get_password_hash, verify_password, verify_plain_bcrypt

SECRET = "test-secret-key-0123456789-0123456789"
PASSWORD = "legacy-pass-123"


def _plain_bcrypt(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _app(get_session, UserModel, **options: Any) -> tuple[CRUDAuth, FastAPI]:
    auth = CRUDAuth(
        session=get_session,
        user_model=UserModel,
        SECRET_KEY=SECRET,
        transports=[SessionTransport(cookies=CookieConfig(secure=False))],
        **options,
    )
    app = FastAPI()
    app.include_router(auth.router)
    return auth, app


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def _user(sessionmaker, UserModel, *, hashed_password: str, **fields: Any) -> None:
    async with sessionmaker() as db:
        await UserRepository(UserModel).create(
            db,
            {
                "email": "old@x.com",
                "username": "old",
                "hashed_password": hashed_password,
                "email_verified": True,
                **fields,
            },
        )


async def _stored_hash(sessionmaker, UserModel) -> str:
    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        return repo.get(await repo.get_by_email(db, "old@x.com"), "hashed_password")


async def _login(app: FastAPI, password: str = PASSWORD) -> httpx.Response:
    async with _client(app) as client:
        return await client.post("/login", data={"username": "old", "password": password})


def test_verify_plain_bcrypt_accepts_its_own_hashes_and_nothing_else() -> None:
    legacy = _plain_bcrypt(PASSWORD)

    assert verify_plain_bcrypt(PASSWORD, legacy) is True
    assert verify_plain_bcrypt("wrong-pass-123", legacy) is False
    assert verify_plain_bcrypt(PASSWORD, "not-a-hash") is False
    assert verify_plain_bcrypt("x" * 100, legacy) is False
    assert verify_password(PASSWORD, legacy) is False


async def test_without_a_legacy_verifier_a_plain_bcrypt_hash_is_refused(
    get_session, UserModel, sessionmaker
) -> None:
    auth, app = _app(get_session, UserModel)
    await auth.initialize()
    await _user(sessionmaker, UserModel, hashed_password=_plain_bcrypt(PASSWORD))

    response = await _login(app)
    await auth.shutdown()

    assert response.status_code == 401


async def test_a_legacy_hash_signs_in_and_is_replaced_with_a_crudauth_one(
    get_session, UserModel, sessionmaker
) -> None:
    auth, app = _app(get_session, UserModel, legacy_verifiers=[verify_plain_bcrypt])
    await auth.initialize()
    legacy = _plain_bcrypt(PASSWORD)
    await _user(sessionmaker, UserModel, hashed_password=legacy)

    first = await _login(app)
    stored = await _stored_hash(sessionmaker, UserModel)
    second = await _login(app)
    await auth.shutdown()

    assert first.status_code == 200
    assert stored != legacy
    assert verify_password(PASSWORD, stored) is True
    assert second.status_code == 200


async def test_a_wrong_password_against_a_legacy_hash_is_refused_and_keeps_the_hash(
    get_session, UserModel, sessionmaker
) -> None:
    auth, app = _app(get_session, UserModel, legacy_verifiers=[verify_plain_bcrypt])
    await auth.initialize()
    legacy = _plain_bcrypt(PASSWORD)
    await _user(sessionmaker, UserModel, hashed_password=legacy)

    response = await _login(app, password="wrong-pass-123")
    stored = await _stored_hash(sessionmaker, UserModel)
    await auth.shutdown()

    assert response.status_code == 401
    assert stored == legacy


async def test_a_crudauth_hash_still_signs_in_with_legacy_verifiers_configured(
    get_session, UserModel, sessionmaker
) -> None:
    auth, app = _app(get_session, UserModel, legacy_verifiers=[verify_plain_bcrypt])
    await auth.initialize()
    modern = get_password_hash(PASSWORD)
    await _user(sessionmaker, UserModel, hashed_password=modern)

    response = await _login(app)
    stored = await _stored_hash(sessionmaker, UserModel)
    await auth.shutdown()

    assert response.status_code == 200
    assert stored == modern


async def test_a_legacy_hash_on_a_disabled_account_is_refused_and_not_rehashed(
    get_session, UserModel, sessionmaker
) -> None:
    auth, app = _app(get_session, UserModel, legacy_verifiers=[verify_plain_bcrypt])
    await auth.initialize()
    legacy = _plain_bcrypt(PASSWORD)
    await _user(sessionmaker, UserModel, hashed_password=legacy, is_active=False)

    response = await _login(app)
    stored = await _stored_hash(sessionmaker, UserModel)
    await auth.shutdown()

    assert response.status_code == 401
    assert stored == legacy


async def test_an_unknown_user_runs_every_legacy_verifier_against_a_dummy_hash(
    get_session, UserModel
) -> None:
    """Timing: a wrong password costs the same whether or not the account exists."""
    seen: list[str] = []

    def counting(plain_password: str, hashed_password: str) -> bool:
        seen.append(hashed_password)
        return True

    auth, app = _app(get_session, UserModel, legacy_verifiers=[counting])
    await auth.initialize()

    async with _client(app) as client:
        response = await client.post("/login", data={"username": "nobody", "password": PASSWORD})
    await auth.shutdown()

    assert response.status_code == 401
    assert len(seen) == 1
    assert seen[0].startswith("$2")


async def test_a_verifier_that_raises_counts_as_a_non_match(
    get_session, UserModel, sessionmaker, caplog
) -> None:
    def broken(plain_password: str, hashed_password: str) -> bool:
        raise RuntimeError("legacy store unavailable")

    auth, app = _app(get_session, UserModel, legacy_verifiers=[broken, verify_plain_bcrypt])
    await auth.initialize()
    await _user(sessionmaker, UserModel, hashed_password=_plain_bcrypt(PASSWORD))

    with caplog.at_level("WARNING", logger="crudauth"):
        response = await _login(app)
    await auth.shutdown()

    assert response.status_code == 200
    assert any(
        "broken" in record.getMessage() and "RuntimeError" in record.getMessage()
        for record in caplog.records
    )
    assert PASSWORD not in caplog.text


class TestRefusedLoginHooks:
    @staticmethod
    def _recording() -> tuple[AuthHooks, list[tuple[str, dict[str, Any]]]]:
        events: list[tuple[str, dict[str, Any]]] = []

        def failed(identifier: str, *, user, reason, context) -> None:
            events.append(
                (
                    "failed",
                    {
                        "identifier": identifier,
                        "user": user,
                        "reason": reason,
                        "ip": context.ip_address,
                    },
                )
            )

        def locked(identifier: str, *, retry_after, context) -> None:
            events.append(("lockout", {"identifier": identifier, "retry_after": retry_after}))

        return AuthHooks(on_login_failed=failed, on_lockout=locked), events

    async def test_a_wrong_password_reports_the_account_it_named(
        self, get_session, UserModel, sessionmaker
    ) -> None:
        hooks, events = self._recording()
        auth, app = _app(get_session, UserModel, hooks=hooks)
        await auth.initialize()
        await _user(sessionmaker, UserModel, hashed_password=get_password_hash(PASSWORD))

        await _login(app, password="wrong-pass-123")
        await auth.shutdown()

        assert [kind for kind, _ in events] == ["failed"]
        detail = events[0][1]
        assert detail["identifier"] == "old"
        assert detail["reason"] == "invalid_credentials"
        assert detail["user"]["username"] == "old"
        assert detail["ip"] is not None

    async def test_an_unknown_identifier_reports_no_account(self, get_session, UserModel) -> None:
        hooks, events = self._recording()
        auth, app = _app(get_session, UserModel, hooks=hooks)
        await auth.initialize()

        async with _client(app) as client:
            await client.post("/login", data={"username": "ghost", "password": PASSWORD})
        await auth.shutdown()

        assert events == [
            (
                "failed",
                {
                    "identifier": "ghost",
                    "user": None,
                    "reason": "invalid_credentials",
                    "ip": events[0][1]["ip"],
                },
            )
        ]

    async def test_a_disabled_account_reports_inactive(
        self, get_session, UserModel, sessionmaker
    ) -> None:
        hooks, events = self._recording()
        auth, app = _app(get_session, UserModel, hooks=hooks)
        await auth.initialize()
        await _user(
            sessionmaker, UserModel, hashed_password=get_password_hash(PASSWORD), is_active=False
        )

        await _login(app)
        await auth.shutdown()

        assert [(kind, detail["reason"]) for kind, detail in events] == [("failed", "inactive")]

    async def test_an_engaged_lockout_reports_the_wait(
        self, get_session, UserModel, sessionmaker
    ) -> None:
        hooks, events = self._recording()
        auth, app = _app(get_session, UserModel, hooks=hooks)
        await auth.initialize()
        await _user(sessionmaker, UserModel, hashed_password=get_password_hash(PASSWORD))
        allowed = auth.runtime.lockout.max_attempts if auth.runtime.lockout else 5

        async with _client(app) as client:
            for _ in range(allowed):
                await client.post("/login", data={"username": "old", "password": "wrong-pass-123"})
            locked = await client.post("/login", data={"username": "old", "password": PASSWORD})
        await auth.shutdown()

        assert locked.status_code == 429
        lockouts = [detail for kind, detail in events if kind == "lockout"]
        assert len(lockouts) == 1
        assert lockouts[0]["identifier"] == "old"
        assert lockouts[0]["retry_after"] > 0

    async def test_a_hook_that_raises_does_not_change_the_answer(
        self, get_session, UserModel, sessionmaker
    ) -> None:
        def broken(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("audit store unavailable")

        auth, app = _app(get_session, UserModel, hooks=AuthHooks(on_login_failed=broken))
        await auth.initialize()
        await _user(sessionmaker, UserModel, hashed_password=get_password_hash(PASSWORD))

        response = await _login(app, password="wrong-pass-123")
        await auth.shutdown()

        assert response.status_code == 401


@pytest.mark.parametrize("legacy", [True, False])
async def test_the_login_hook_names_the_session_by_its_public_handle(
    get_session, UserModel, sessionmaker, legacy
) -> None:
    handles: list[str | None] = []

    def logged_in(user, *, request, context) -> None:
        handles.append(context.session_handle)

    auth, app = _app(
        get_session,
        UserModel,
        hooks=AuthHooks(on_after_login=logged_in),
        legacy_verifiers=[verify_plain_bcrypt],
    )
    await auth.initialize()
    hashed = _plain_bcrypt(PASSWORD) if legacy else get_password_hash(PASSWORD)
    await _user(sessionmaker, UserModel, hashed_password=hashed)

    async with _client(app) as client:
        await client.post("/login", data={"username": "old", "password": PASSWORD})
        session_id = client.cookies.get("session_id")
    await auth.shutdown()

    assert session_id is not None
    assert handles == [auth.sessions.session_handle(session_id)]


async def test_the_digest_crudauth_hashes_is_not_a_second_password(
    get_session, UserModel, sessionmaker
) -> None:
    """crudauth stores bcrypt(base64(sha256(pw))), so plain bcrypt would accept that digest as the password."""
    auth, app = _app(get_session, UserModel, legacy_verifiers=[verify_plain_bcrypt])
    await auth.initialize()
    await _user(sessionmaker, UserModel, hashed_password=get_password_hash(PASSWORD))
    digest = base64.b64encode(hashlib.sha256(PASSWORD.encode()).digest()).decode()

    response = await _login(app, password=digest)
    await auth.shutdown()

    assert response.status_code == 401


def test_verify_plain_bcrypt_refuses_crudauths_own_pre_hash() -> None:
    digest = base64.b64encode(hashlib.sha256(PASSWORD.encode()).digest()).decode()

    assert verify_plain_bcrypt(digest, get_password_hash(PASSWORD)) is False
    assert verify_plain_bcrypt(digest, _plain_bcrypt(digest)) is False


class TestALongLegacyPassword:
    """bcrypt only ever hashed the first 72 bytes, so a plain-bcrypt hash of a long password covers those."""

    LONG = "correct horse battery staple " * 3 + "é" * 4

    def _stored_by_an_older_library(self) -> str:
        return bcrypt.hashpw(self.LONG.encode()[:72], bcrypt.gensalt()).decode()

    def test_the_full_password_matches_what_the_old_system_stored(self) -> None:
        assert len(self.LONG.encode()) > 72
        assert verify_plain_bcrypt(self.LONG, self._stored_by_an_older_library()) is True

    def test_past_72_bytes_the_old_system_never_looked(self) -> None:
        """The same as the old system: only someone who knows the first 72 bytes gets in this way."""
        stored = self._stored_by_an_older_library()

        assert verify_plain_bcrypt(self.LONG[:72] + " and then anything", stored) is True
        assert verify_plain_bcrypt("different start " + self.LONG, stored) is False

    def test_a_cut_through_a_multibyte_character_still_matches(self) -> None:
        password = "a" * 71 + "é" + "tail"
        stored = bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt()).decode()

        assert verify_plain_bcrypt(password, stored) is True

    async def test_a_long_legacy_password_signs_in_and_every_byte_counts_afterwards(
        self, get_session, UserModel, sessionmaker
    ) -> None:
        auth, app = _app(get_session, UserModel, legacy_verifiers=[verify_plain_bcrypt])
        await auth.initialize()
        await _user(sessionmaker, UserModel, hashed_password=self._stored_by_an_older_library())

        migrated = await _login(app, password=self.LONG)
        stored = await _stored_hash(sessionmaker, UserModel)
        await auth.shutdown()

        assert migrated.status_code == 200
        assert verify_password(self.LONG, stored) is True
        assert verify_password(self.LONG[:-1], stored) is False
