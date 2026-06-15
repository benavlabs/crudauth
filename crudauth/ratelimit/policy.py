"""Escalating login-lockout policy, built over the dumb backend primitives.

Relocated out of ``SessionManager`` into the kernel so it reads
``runtime.rate_limiter`` rather than a limiter the transport built. Per-IP and
per-username failure counters with exponential backoff and round retention.
"""

from __future__ import annotations

import logging
from typing import Literal

from ..constants import (
    DEFAULT_LOGIN_ATTEMPT_WINDOW_SECONDS,
    DEFAULT_LOGIN_LOCKOUT_BASE_SECONDS,
    DEFAULT_LOGIN_LOCKOUT_MAX_SECONDS,
    DEFAULT_LOGIN_MAX_ATTEMPTS,
    DEFAULT_LOGIN_ROUND_RETENTION_SECONDS,
)
from .base import RateLimiterBackend
from .constants import LOCKOUT_NAMESPACE

__all__ = ["LockoutPolicy"]

logger = logging.getLogger("crudauth.ratelimit")


class LockoutPolicy:
    """Tracks failed logins and escalates lockout duration across rounds.

    Fails **closed** by default: if the backend errors, a login attempt is
    blocked rather than silently allowed. Rationale: under fail-open an attacker
    who can DoS the limiter backend then brute-forces with lockout disabled.

    Note:
        Fail-closed means a network-backend outage blocks logins; pair a redis
        backend with HA redis (the in-memory backend has no outage mode).

    Args:
        backend: The shared rate-limiter backend (counters live here).
        max_attempts: Failures allowed within ``attempt_window_seconds`` before
            a lockout trips.
        attempt_window_seconds: Sliding window for counting failures.
        lockout_base_seconds: First lockout duration; doubles each round.
        lockout_max_seconds: Cap on the exponential lockout duration.
        round_retention_seconds: How long a round counter persists, so repeat
            offenders resume escalating rather than resetting. The TTL is slid
            forward on every lockout (sliding window), so a slow, paced attack
            keeps climbing the escalation ladder instead of forgetting it.
        on_login_success: What a successful login clears.
            ``"clear_all"`` (default) clears both the per-username and per-IP
            failure pressure - friendly to legitimate users behind a shared
            egress (corporate NAT / mobile CGNAT), at the cost of letting a
            co-located attacker's per-IP budget be refreshed by an unrelated
            user's success. ``"clear_user_only"`` clears just the username
            dimension, keeping per-IP pressure - tighter against a single-source
            brute force, but only safe when your per-IP key reliably identifies
            an individual client (you terminate behind a proxy with
            ``trusted_proxy_hops`` set AND your users aren't predominantly behind
            shared egress); otherwise it can lock out innocent co-located users.
            The lockout's primary key is ``ip + username`` together; this governs
            only the secondary per-IP pressure valve on success.
        fail_open: On a backend error, allow (``True``) or block (``False``).
    """

    def __init__(
        self,
        backend: RateLimiterBackend,
        *,
        max_attempts: int = DEFAULT_LOGIN_MAX_ATTEMPTS,
        attempt_window_seconds: int = DEFAULT_LOGIN_ATTEMPT_WINDOW_SECONDS,
        lockout_base_seconds: int = DEFAULT_LOGIN_LOCKOUT_BASE_SECONDS,
        lockout_max_seconds: int = DEFAULT_LOGIN_LOCKOUT_MAX_SECONDS,
        round_retention_seconds: int = DEFAULT_LOGIN_ROUND_RETENTION_SECONDS,
        on_login_success: Literal["clear_all", "clear_user_only"] = "clear_all",
        fail_open: bool = False,
    ):
        self.backend = backend
        self.max_attempts = max_attempts
        self.attempt_window = attempt_window_seconds
        self.lockout_base = lockout_base_seconds
        self.lockout_max = lockout_max_seconds
        self.round_retention = round_retention_seconds
        self.on_login_success = on_login_success
        self.fail_open = fail_open

    async def check_and_record(
        self, ip_address: str, username: str, success: bool = False
    ) -> tuple[bool, int | None, int]:
        """Record an attempt and report whether it's allowed.

        Args:
            ip_address: Caller IP (one of the two keyed dimensions).
            username: Submitted username/email (the other dimension).
            success: When ``True``, clears all counters for this pair and allows.

        Returns:
            ``(allowed, attempts_remaining, retry_after_seconds)``.

        Note:
            The escalation branch issues several sequential backend ops (per-IP
            and per-username lock + round counters). It runs only on *repeated
            failures* (already past the attempt cap), so it's intentionally not
            pipelined - the hot success/under-cap paths stay at one or two ops.
        """
        ns = LOCKOUT_NAMESPACE
        ip_attempts = f"{ns}:ip:{ip_address}"
        user_attempts = f"{ns}:user:{username}"
        ip_lock = f"{ns}:lock:ip:{ip_address}"
        user_lock = f"{ns}:lock:user:{username}"
        ip_rounds = f"{ns}:rounds:ip:{ip_address}"
        user_rounds = f"{ns}:rounds:user:{username}"
        b = self.backend

        try:
            if success:
                cleared = [user_attempts, user_lock, user_rounds]
                if self.on_login_success == "clear_all":
                    cleared += [ip_attempts, ip_lock, ip_rounds]
                for key in cleared:
                    await b.delete(key)
                return True, None, 0

            active_lockout = max(await b.get_ttl(ip_lock), await b.get_ttl(user_lock))
            if active_lockout > 0:
                return False, 0, active_lockout

            ip_count = await b.increment(ip_attempts, 1, self.attempt_window)
            user_count = await b.increment(user_attempts, 1, self.attempt_window)
            attempt_count = max(ip_count, user_count)
            remaining = max(0, self.max_attempts - attempt_count)
            if attempt_count <= self.max_attempts:
                return True, remaining, 0

            rounds = max((await b.get_count(ip_rounds)) or 0, (await b.get_count(user_rounds)) or 0)
            retry_after = min(self.lockout_base * (2**rounds), self.lockout_max)
            round_ttl = max(retry_after, self.round_retention)
            await b.increment(ip_lock, 1, retry_after)
            await b.increment(user_lock, 1, retry_after)
            await b.increment_and_refresh_ttl(ip_rounds, 1, round_ttl)
            await b.increment_and_refresh_ttl(user_rounds, 1, round_ttl)
            return False, 0, retry_after
        except Exception as exc:
            logger.warning("lockout backend error (fail_open=%s): %s", self.fail_open, exc)
            if self.fail_open:
                return True, None, 0
            return False, 0, self.lockout_base
