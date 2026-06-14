"""Unit tests for primitives: tokens, password hashing, OAuth linking, column_map."""

from __future__ import annotations

from datetime import timedelta


from crudauth.oauth import OAuthAccountService, OAuthUserInfo
from crudauth.repository import UserRepository
from crudauth.transports.bearer.tokens import (
    TokenType,
    create_access_token,
    create_signed_token,
    is_expired_token,
    verify_signed_token,
    verify_token,
)
from starlette.requests import Request

from crudauth.utils import (
    canonical_email,
    canonical_identifier,
    dummy_verify_password,
    get_client_ip,
    get_password_hash,
    make_unusable_password,
    mask_email,
    verify_password,
)

SECRET = "test-secret-key-0123456789-0123456789"


def _request(headers: dict[str, str] | None = None, client_host: str = "10.0.0.1") -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "headers": [(k.encode(), v.encode()) for k, v in (headers or {}).items()],
            "client": (client_host, 1234),
        }
    )


# --- password hashing --------------------------------------------------------
def test_password_roundtrip() -> None:
    h = get_password_hash("hunter2")
    assert verify_password("hunter2", h)
    assert not verify_password("wrong", h)


def test_verify_password_handles_malformed_hash() -> None:
    assert verify_password("anything", "not-a-bcrypt-hash") is False


def test_unusable_password_never_verifies() -> None:
    sentinel = make_unusable_password()
    assert not verify_password("", sentinel)
    assert not verify_password("password", sentinel)


def test_canonical_email() -> None:
    assert canonical_email("  Foo@X.com ") == "foo@x.com"
    assert canonical_email(None) is None


def test_mask_email() -> None:
    assert mask_email("john@example.com") == "j***@example.com"
    assert mask_email("ab@x.io") == "a***@x.io"
    assert mask_email("a@x.io") == "a***@x.io"  # single-char local doesn't leak more
    assert mask_email("not-an-email") == "***"
    assert mask_email("") == "***"


def test_long_password_not_truncated_at_72_bytes() -> None:
    # Two passwords sharing a 72-byte prefix must NOT be interchangeable
    # (bcrypt alone truncates at 72 bytes; the SHA-256 pre-hash prevents it).
    base = "a" * 72
    h = get_password_hash(base + "X")
    assert verify_password(base + "X", h)
    assert not verify_password(base + "Y", h)
    assert not verify_password(base, h)


def test_password_roundtrip_very_long() -> None:
    pw = "correct horse battery staple " * 10
    assert verify_password(pw, get_password_hash(pw))


def test_dummy_verify_password_runs_without_raising() -> None:
    # Exercises the absent-user timing-equalization path; must not raise.
    dummy_verify_password("whatever")


# --- login identifier canonicalization (lockout key) -------------------------
def test_canonical_identifier_normalizes_email_case() -> None:
    assert canonical_identifier("V@X.com") == "v@x.com"
    assert canonical_identifier("  Foo@x.com ") == "foo@x.com"


def test_canonical_identifier_leaves_usernames_untouched() -> None:
    assert canonical_identifier("Alice") == "Alice"


# --- client IP / trusted proxy ----------------------------------------------
def test_get_client_ip_ignores_xff_without_trusted_hops() -> None:
    req = _request({"x-forwarded-for": "1.2.3.4"}, client_host="10.0.0.1")
    assert get_client_ip(req) == "10.0.0.1"


def test_get_client_ip_uses_socket_peer_by_default() -> None:
    assert get_client_ip(_request(client_host="203.0.113.9")) == "203.0.113.9"


def test_get_client_ip_single_trusted_hop() -> None:
    req = _request({"x-forwarded-for": "1.2.3.4"}, client_host="10.0.0.1")
    assert get_client_ip(req, trusted_hops=1) == "1.2.3.4"


def test_get_client_ip_ignores_prepended_spoof() -> None:
    # Attacker prepends a fake left-most value; one trusted hop reads the
    # right-most entry (set by our proxy), not the spoof.
    req = _request({"x-forwarded-for": "9.9.9.9, 1.2.3.4"}, client_host="10.0.0.1")
    assert get_client_ip(req, trusted_hops=1) == "1.2.3.4"


def test_get_client_ip_two_trusted_hops() -> None:
    req = _request({"x-forwarded-for": "1.2.3.4, 172.16.0.1"}, client_host="10.0.0.1")
    assert get_client_ip(req, trusted_hops=2) == "1.2.3.4"


def test_get_client_ip_chain_shorter_than_hops_clamps_to_leftmost() -> None:
    req = _request({"x-forwarded-for": "1.2.3.4"}, client_host="10.0.0.1")
    assert get_client_ip(req, trusted_hops=5) == "1.2.3.4"


# --- jwt tokens --------------------------------------------------------------
def test_access_token_roundtrip() -> None:
    token = create_access_token({"sub": "42"}, SECRET, scopes=["a", "b"])
    payload = verify_token(token, SECRET, TokenType.ACCESS)
    assert payload is not None
    assert payload["sub"] == "42"
    assert payload["scopes"] == ["a", "b"]


def test_access_token_wrong_type_rejected() -> None:
    token = create_access_token({"sub": "42"}, SECRET)
    assert verify_token(token, SECRET, TokenType.REFRESH) is None


def test_token_wrong_secret_rejected() -> None:
    token = create_access_token({"sub": "42"}, SECRET)
    assert verify_token(token, "wrong-secret-key-0123456789-0123456789", TokenType.ACCESS) is None


def test_expired_token_rejected() -> None:
    token = create_access_token({"sub": "42"}, SECRET, expires_delta=timedelta(seconds=-1))
    assert verify_token(token, SECRET, TokenType.ACCESS) is None


def test_is_expired_token_distinguishes_expiry_from_tampering() -> None:
    valid = create_access_token({"sub": "1"}, SECRET)
    expired = create_access_token({"sub": "1"}, SECRET, expires_delta=timedelta(seconds=-1))
    assert is_expired_token(valid, SECRET) is False
    assert is_expired_token(expired, SECRET) is True
    assert is_expired_token("garbage", SECRET) is False
    # expired AND wrong signature reads as tampered (signature checked first), not "just expired"
    assert is_expired_token(expired, "wrong-secret-key-0123456789-0123456789") is False


def test_signed_token_purpose() -> None:
    token = create_signed_token(SECRET, 7, "verify_email")
    assert verify_signed_token(token, SECRET, "verify_email") == "7"
    assert verify_signed_token(token, SECRET, "reset_password") is None


# --- oauth account linking ---------------------------------------------------
async def test_token_version_increments(sessionmaker, UserModel) -> None:
    repo = UserRepository(UserModel)
    async with sessionmaker() as db:
        user = await repo.create(
            db, {"email": "tv@x.com", "username": "tv", "hashed_password": "h"}
        )
        assert repo.token_version(user) == 0
        await repo.increment_token_version(db, user)
        assert repo.token_version(user) == 1


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


# --- column_map --------------------------------------------------------------
def test_column_map_translation(UserModel) -> None:
    repo = UserRepository(UserModel, column_map={"email": "email", "id": "id"})
    assert repo.col("email") == "email"
    repo2 = UserRepository(UserModel, column_map={"hashed_password": "email"})
    assert repo2.col("hashed_password") == "email"
