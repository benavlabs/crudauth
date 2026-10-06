"""Password hashing and verification, and the unusable-password sentinel."""

from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import logging
import secrets
import unicodedata
from collections.abc import Callable, Sequence

import bcrypt
from fastapi.concurrency import run_in_threadpool

logger = logging.getLogger("crudauth")

PRE_HASH_LENGTH = 44
"""Characters in crudauth's bcrypt input: a SHA-256 digest (32 bytes) in base64."""

BCRYPT_INPUT_BYTES = 72
"""The most of a password bcrypt has ever hashed: older libraries cut there, newer ones refuse more."""

__all__ = [
    "normalize_password",
    "get_password_hash",
    "get_password_hash_async",
    "verify_password",
    "verify_password_async",
    "verify_and_update_password",
    "verify_and_update_password_async",
    "dummy_verify_password",
    "LegacyVerifier",
    "verify_plain_bcrypt",
    "verify_legacy_password",
    "verify_legacy_password_async",
    "make_unusable_password",
    "is_unusable_password",
]


LegacyVerifier = Callable[[str, str], bool]
"""Checks a password against a hash another system wrote: ``(plain_password, hashed_password) -> bool``."""


def _bcrypt_input(password: str) -> bytes:
    """Length-normalize the password for bcrypt; not the password hash itself.

    bcrypt silently ignores input past 72 bytes, which would make two long
    passwords sharing a 72-byte prefix interchangeable. Hashing to SHA-256 and
    base64-encoding yields a fixed 44-byte value (well under 72) that depends on
    every byte typed, so the bcrypt comparison covers the whole password.

    Note:
        The actual password KDF is bcrypt (slow, salted, in [get_password_hash]
        [crudauth.utils.get_password_hash]); this SHA-256 step is only a
        fixed-width transform and is never stored or relied on for slowness. A
        static analyzer may flag the SHA-256 call as "weak password hashing" -
        that is a false positive, since the stored hash is bcrypt, not this
        digest. This is the same construction Django and passlib use.
    """
    digest = hashlib.sha256(password.encode()).digest()
    return base64.b64encode(digest)


def normalize_password(password: str) -> str:
    """Unicode-normalize a password (NFKC) so every way of typing it hashes the same.

    ``é`` typed as one precomposed code point and as ``e`` plus a combining accent
    normalize to the same string, as NIST SP 800-63B recommends.
    """
    return unicodedata.normalize("NFKC", password)


def get_password_hash(password: str) -> str:
    """Hash a plaintext password with bcrypt (random salt per call).

    The password is NFKC-normalized (see [normalize_password]
    [crudauth.utils.normalize_password]) and SHA-256 pre-hashed before bcrypt
    (see [_bcrypt_input][crudauth.utils.hashing._bcrypt_input]), so there is no effective
    length ceiling and no silent truncation. This call blocks for the bcrypt
    work; use [get_password_hash_async][crudauth.utils.get_password_hash_async]
    inside an async route.

    Example:
        ```python
        await auth.repo.create(db, {"email": e, "hashed_password": get_password_hash(pw)})
        ```
    """
    hashed: bytes = bcrypt.hashpw(_bcrypt_input(normalize_password(password)), bcrypt.gensalt())
    return hashed.decode()


async def get_password_hash_async(password: str) -> str:
    """[get_password_hash][crudauth.utils.get_password_hash] in a worker thread, off the event loop.

    Example:
        ```python
        hashed = await get_password_hash_async(pw)
        await auth.repo.update(db, user, {"hashed_password": hashed})
        ```
    """
    return await run_in_threadpool(get_password_hash, password)


def _checkpw(password: str, hashed_password: str | None) -> bool:
    try:
        return bcrypt.checkpw(_bcrypt_input(password), (hashed_password or "").encode())
    except (ValueError, TypeError):
        bcrypt.checkpw(_bcrypt_input(""), _dummy_hash().encode())
        return False


def _matching_form(plain_password: str, hashed_password: str | None) -> str | None:
    normalized = normalize_password(plain_password)
    if _checkpw(normalized, hashed_password):
        return normalized
    if plain_password != normalized and _checkpw(plain_password, hashed_password):
        return plain_password
    return None


def verify_password(plain_password: str, hashed_password: str | None) -> bool:
    """Verify a plaintext password against a bcrypt hash.

    The NFKC-normalized password is checked first, then the password as typed,
    so hashes created before normalization keep verifying.

    Returns ``False`` (rather than raising) when the stored hash is missing,
    empty, the unusable sentinel, or malformed, so a corrupted row produces a
    clean "invalid password" path instead of a 500. Those cases still pay a full
    bcrypt verification, so an account without a verifiable hash answers in the
    same time as one with a real hash. This call blocks for the bcrypt work; use
    [verify_password_async][crudauth.utils.verify_password_async] inside an async
    route.

    Example:
        ```python
        if not verify_password(form.password, auth.repo.get(user, "hashed_password")):
            raise UnauthorizedException("Incorrect username or password")
        ```
    """
    return _matching_form(plain_password, hashed_password) is not None


async def verify_password_async(plain_password: str, hashed_password: str | None) -> bool:
    """[verify_password][crudauth.utils.verify_password] in a worker thread, off the event loop.

    Example:
        ```python
        if not await verify_password_async(form.password, auth.repo.get(user, "hashed_password")):
            raise UnauthorizedException("Incorrect username or password")
        ```
    """
    return await run_in_threadpool(verify_password, plain_password, hashed_password)


def verify_and_update_password(
    plain_password: str, hashed_password: str | None
) -> tuple[bool, str | None]:
    """Verify a password and return a replacement hash when the stored one predates normalization.

    Verification is the same as [verify_password][crudauth.utils.verify_password].

    Returns:
        ``(verified, new_hash)``. ``new_hash`` is a fresh hash of the normalized
        password when the stored hash only matched the password as typed (a hash
        created before normalization), and ``None`` otherwise.

    Example:
        ```python
        verified, new_hash = verify_and_update_password(pw, auth.repo.get(user, "hashed_password"))
        if verified and new_hash is not None:
            await auth.repo.update(db, user, {"hashed_password": new_hash})
        ```
    """
    matched = _matching_form(plain_password, hashed_password)
    if matched is None:
        return False, None
    if matched == normalize_password(plain_password):
        return True, None
    return True, get_password_hash(plain_password)


async def verify_and_update_password_async(
    plain_password: str, hashed_password: str | None
) -> tuple[bool, str | None]:
    """[verify_and_update_password][crudauth.utils.verify_and_update_password] in a worker thread, off the event loop."""
    return await run_in_threadpool(verify_and_update_password, plain_password, hashed_password)


@functools.cache
def _dummy_hash() -> str:
    """A real bcrypt hash of a random value, computed once and cached.

    Used to equalize login timing: see [dummy_verify_password]
    [crudauth.utils.dummy_verify_password].
    """
    return get_password_hash(secrets.token_urlsafe(32))


def dummy_verify_password(plain_password: str) -> None:
    """Run a throwaway bcrypt verification and discard the result.

    For a hand-written flow's user-not-found branch, so the absent-user path
    pays the same bcrypt cost as the existing-user path; without it, a missing
    account returns measurably faster and becomes a user-enumeration oracle.
    [verify_password][crudauth.utils.verify_password] with a ``None`` hash does
    the same work.
    """
    verify_password(plain_password, _dummy_hash())


def make_unusable_password() -> str:
    """Return a sentinel that no input can ever verify against.

    Used for OAuth-only accounts. The leading ``!`` makes the value an invalid
    bcrypt hash, so [verify_password][crudauth.utils.verify_password] always returns ``False`` for it. The
    random suffix makes every sentinel unique. Mirrors Django's
    ``set_unusable_password``.

    Example:
        ```python
        # an OAuth-created account with no password yet
        await auth.repo.create(db, {"email": e, "hashed_password": make_unusable_password()})
        ```
    """
    return "!" + secrets.token_urlsafe(16)


def is_unusable_password(hashed_password: str) -> bool:
    """Whether ``hashed_password`` is the unusable sentinel (or empty).

    ``True`` means the account has no real password set - an OAuth-only account
    (see [make_unusable_password][crudauth.utils.make_unusable_password], whose
    sentinel starts with ``!``, never a valid bcrypt hash).

    Example:
        ```python
        if is_unusable_password(auth.repo.get(user, "hashed_password", "")):
            ...  # OAuth-only: offer /set-password rather than a password change
        ```
    """
    return not hashed_password or hashed_password.startswith("!")


def verify_plain_bcrypt(plain_password: str, hashed_password: str) -> bool:
    """A [LegacyVerifier][crudauth.utils.LegacyVerifier] for hashes made by plain bcrypt.

    Plain bcrypt hashes the password itself, where crudauth hashes its SHA-256
    digest, so a hash another library wrote with ``bcrypt.hashpw(password, salt)``
    never matches crudauth's own check. Pass this in ``legacy_verifiers`` to accept
    those hashes at login; each one is replaced with a crudauth hash the first time
    its owner signs in.

    Only the first 72 bytes of the password are compared, because that is all bcrypt
    ever hashed: older libraries cut a longer password there silently, and newer ones
    refuse it. Cutting the same way gives the answer the old system gave on any bcrypt
    version, so a user with a long password migrates too, and their new crudauth hash
    is made from the whole password. A value that isn't a bcrypt hash is a non-match.
    This is for plain bcrypt only: a hasher that pre-hashed before bcrypt (passlib's
    ``bcrypt_sha256``, Django's ``BCryptSHA256PasswordHasher``) needs a verifier of its own.

    It refuses a password shaped like crudauth's own bcrypt input (44 characters of
    base64 that decode to 32 bytes). crudauth stores ``bcrypt(base64(sha256(pw)))``,
    which plain bcrypt would accept for that digest, so without the check an unsalted
    SHA-256 of any user's password, leaked from somewhere else, would sign in as them.
    A real password of exactly that shape is refused by this verifier too, which only
    matters for an account still on its legacy hash.

    Example:
        ```python
        from crudauth.utils import verify_plain_bcrypt

        auth = CRUDAuth(..., legacy_verifiers=[verify_plain_bcrypt])
        ```
    """
    if _looks_like_pre_hash(plain_password):
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode()[:BCRYPT_INPUT_BYTES], hashed_password.encode()
        )
    except ValueError:
        return False


def _looks_like_pre_hash(value: str) -> bool:
    """Whether ``value`` has the shape of crudauth's bcrypt input, a base64 SHA-256 digest."""
    if len(value) != PRE_HASH_LENGTH:
        return False
    try:
        return len(base64.b64decode(value, validate=True)) == hashlib.sha256().digest_size
    except (binascii.Error, ValueError):
        return False


def verify_legacy_password(
    verifiers: Sequence[LegacyVerifier], plain_password: str, hashed_password: str | None
) -> bool:
    """Whether any of ``verifiers`` accepts the password for this hash.

    With no hash (an unknown user) every verifier still runs, against crudauth's
    dummy hash, so a wrong password costs the same whether or not the account
    exists. A verifier that raises counts as a non-match, and is logged so a broken
    one doesn't look like every legacy user typing the wrong password.

    A verifier must not accept crudauth's own hashes for anything but the user's real
    password: crudauth's hashes are bcrypt too, and a check like plain bcrypt's would
    accept the digest crudauth bcrypts (see [verify_plain_bcrypt]
    [crudauth.utils.verify_plain_bcrypt]).
    """
    target = hashed_password or _dummy_hash()
    matched = False
    for verify in verifiers:
        try:
            matched = verify(plain_password, target) or matched
        except Exception as error:
            logger.warning(
                "crudauth: legacy verifier %s raised %s; treated as a non-match",
                getattr(verify, "__qualname__", repr(verify)),
                type(error).__name__,
            )
    return matched and hashed_password is not None


async def verify_legacy_password_async(
    verifiers: Sequence[LegacyVerifier], plain_password: str, hashed_password: str | None
) -> bool:
    """[verify_legacy_password][crudauth.utils.hashing.verify_legacy_password] in a worker thread, off the event loop."""
    return await run_in_threadpool(
        verify_legacy_password, verifiers, plain_password, hashed_password
    )
