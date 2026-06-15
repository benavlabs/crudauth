"""Register-only tuning constants.

The registration *gating* contract (``REGISTRATION_ALLOWED_FIELDS`` /
``REGISTRATION_GATED_FIELDS``) and the shared ``MIN_PASSWORD_LENGTH`` stay in the
top-level [crudauth.constants][] because they're consumed by the spine
(``repository.py`` enforces the allowlist; the email reset flow and
``/set-password`` share the password floor) - moving them here would invert the
import direction (spine importing from a feature).
"""

from __future__ import annotations

from ..constants import SECONDS_PER_MINUTE

# Per-IP self-registration throttle (a register-spray brake at the edge).
REGISTER_MAX_ATTEMPTS = 5
REGISTER_WINDOW_SECONDS = 10 * SECONDS_PER_MINUTE
