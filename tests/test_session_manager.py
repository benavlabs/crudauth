"""Unit tests for SessionManager + storage + login lockout (no HTTP layer)."""

from __future__ import annotations

from starlette.requests import Request

from crudauth.ratelimit import LockoutPolicy, MemoryRateLimiterBackend
from crudauth.storage import MemorySessionStorage, get_session_storage
from crudauth.storage.base import AbstractSessionStorage
from crudauth.transports.session import SessionManager
from crudauth.transports.session.constants import CSRF_TOKEN_ID_META_KEY
from crudauth.transports.session.schemas import SessionData


def make_request(headers=None) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "headers": [(k.encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": ("1.2.3.4", 1234),
    }
    return Request(scope)


def build_manager(max_sessions=5) -> SessionManager:
    return SessionManager(
        get_session_storage("memory", prefix="session:"),
        csrf_storage=get_session_storage("memory", prefix="csrf:"),
        max_sessions_per_user=max_sessions,
        lockout=LockoutPolicy(MemoryRateLimiterBackend(), max_attempts=3, fail_open=False),
    )


async def test_create_and_validate() -> None:
    mgr = build_manager()
    sid, csrf = await mgr.create_session(make_request(), user_id=1)
    session = await mgr.validate_session(sid)
    assert session is not None
    assert session.user_id == 1
    assert await mgr.validate_csrf_token(sid, csrf) is True
    assert await mgr.validate_csrf_token(sid, "bogus") is False


async def test_regenerate_csrf_rotates() -> None:
    mgr = build_manager()
    sid, old = await mgr.create_session(make_request(), user_id=1)
    assert await mgr.validate_csrf_token(sid, old) is True

    new = await mgr.regenerate_csrf_token(user_id=1, session_id=sid)
    assert new and new != old
    # old token is invalidated, new token is accepted
    assert await mgr.validate_csrf_token(sid, old) is False
    assert await mgr.validate_csrf_token(sid, new) is True
    # the session now points at the NEW token (so its TTL is what slides)
    session = await mgr.storage.get(sid, SessionData)
    assert session is not None
    assert session.metadata[CSRF_TOKEN_ID_META_KEY] == new


async def test_regenerate_csrf_missing_session_returns_empty() -> None:
    mgr = build_manager()
    assert await mgr.regenerate_csrf_token(user_id=1, session_id="nope") == ""


async def test_revoke() -> None:
    mgr = build_manager()
    sid, _ = await mgr.create_session(make_request(), user_id=1)
    assert await mgr.revoke(sid, owner_id=1) is True
    assert await mgr.validate_session(sid) is None


async def test_revoke_wrong_owner() -> None:
    mgr = build_manager()
    sid, _ = await mgr.create_session(make_request(), user_id=1)
    assert await mgr.revoke(sid, owner_id=999) is False
    assert await mgr.validate_session(sid) is not None


async def test_list_and_revoke_all() -> None:
    mgr = build_manager()
    await mgr.create_session(make_request(), user_id=7)
    await mgr.create_session(make_request(), user_id=7)
    sessions = await mgr.list_for_user(7)
    assert len(sessions) == 2
    n = await mgr.revoke_all(7)
    assert n == 2
    assert await mgr.list_for_user(7) == []


async def test_max_sessions_enforced() -> None:
    mgr = build_manager(max_sessions=2)
    for _ in range(3):
        await mgr.create_session(make_request(), user_id=5)
    sessions = await mgr.list_for_user(5)
    assert len(sessions) == 2


async def test_login_lockout() -> None:
    mgr = build_manager()
    allowed = True
    for _ in range(3):
        allowed, remaining, retry = await mgr.track_login_attempt("1.1.1.1", "bob", success=False)
    # 4th failed attempt should trip lockout
    allowed, remaining, retry = await mgr.track_login_attempt("1.1.1.1", "bob", success=False)
    assert allowed is False
    assert retry > 0


async def test_login_success_resets() -> None:
    mgr = build_manager()
    await mgr.track_login_attempt("2.2.2.2", "carol", success=False)
    allowed, _, _ = await mgr.track_login_attempt("2.2.2.2", "carol", success=True)
    assert allowed is True


async def test_memory_storage_crud() -> None:
    store: MemorySessionStorage = MemorySessionStorage(prefix="t:", expiration=100)
    sid = await store.create(SessionData(user_id=1), session_id="abc")
    assert sid == "abc"
    assert await store.exists("abc")
    got = await store.get("abc", SessionData)
    assert got is not None and got.user_id == 1
    assert await store.delete("abc") is True
    assert await store.get("abc", SessionData) is None


async def test_minimal_backend_degrades_gracefully() -> None:
    # a BYO backend that implements only the core surface (no
    # get_user_sessions / scan_keys) must degrade - not crash - disabling
    # multi-device listing and the idle sweep rather than raising.
    class MinimalStorage(AbstractSessionStorage[SessionData]):
        def __init__(self) -> None:
            super().__init__()
            self._d: dict[str, SessionData] = {}

        async def create(self, data, session_id=None, expiration=None) -> str:
            sid = session_id or self.generate_session_id()
            self._d[sid] = data
            return sid

        async def get(self, session_id, model_class):
            return self._d.get(session_id)

        async def update(self, session_id, data, reset_expiration=True, expiration=None) -> bool:
            if session_id not in self._d:
                return False
            self._d[session_id] = data
            return True

        async def delete(self, session_id, user_id=None) -> bool:
            return self._d.pop(session_id, None) is not None

        async def extend(self, session_id, expiration=None) -> bool:
            return session_id in self._d

        async def exists(self, session_id) -> bool:
            return session_id in self._d

    mgr = SessionManager(MinimalStorage())
    await mgr.create_session(make_request(), user_id=1)
    # capability-dependent features degrade to no-ops, no NotImplementedError leak
    assert await mgr.list_for_user(1) == []
    assert await mgr.revoke_all(1) == 0
    await mgr.cleanup_expired_sessions(force=True)  # must not raise
