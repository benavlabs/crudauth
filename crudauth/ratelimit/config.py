"""Rate-limit policy values and key strategy (code, not DB rows)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..constants import SECONDS_PER_HOUR

__all__ = ["RateLimit", "KeyBy", "DEFAULT_RATE_LIMITS"]


@dataclass(frozen=True)
class RateLimit:
    """A fixed-window allowance: ``times`` events per ``seconds``.

    ``times=0`` disables the limit (an explicit, documented off switch, never the
    low-friction default).

    Example:
        ```python
        CRUDAuth(..., rate_limits={"password_reset_request": RateLimit(3, 1800)})
        ```
    """

    times: int
    seconds: int

    @property
    def disabled(self) -> bool:
        """True when ``times == 0`` (the limit is turned off)."""
        return self.times == 0


class KeyBy(str, Enum):
    """Which dimension a [CRUDAuth.rate_limit][crudauth.crud_auth.CRUDAuth.rate_limit] dependency keys on."""

    IP = "ip"
    USER = "user"


# Auth-adjacent endpoints protected out of the box. Apps tune via
# ``CRUDAuth(rate_limits={...})`` but can't ship them unprotected. Login is not
# here - it uses the escalating LockoutPolicy, configured on SessionTransport.
DEFAULT_RATE_LIMITS: dict[str, RateLimit] = {
    "register": RateLimit(times=5, seconds=SECONDS_PER_HOUR),
    "email_verify_request": RateLimit(times=5, seconds=SECONDS_PER_HOUR),
    "password_reset_request": RateLimit(times=5, seconds=SECONDS_PER_HOUR),
    "email_change_request": RateLimit(times=3, seconds=SECONDS_PER_HOUR),
    "existing_account_notice": RateLimit(times=5, seconds=SECONDS_PER_HOUR),
}
