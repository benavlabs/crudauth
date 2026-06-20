"""Constants for the email flows."""

from __future__ import annotations

from typing import Literal, get_args

# Signed-token purposes (the ``purpose`` claim each flow's token carries).
VERIFY = "verify_email"
RESET = "reset_password"
CHANGE = "change_email"

# The message kinds crudauth asks the adapter to deliver. ``verify_email`` is the
# recovery-factor verification for an email-recovery app; ``verify_recovery`` is the
# same for any other factor (so a non-email channel isn't handed an "email"-named
# kind). ``existing_account`` is a security notice ("someone tried to register with
# your email"), distinct from the cheery ``welcome``.
EmailKind = Literal[
    "verify_email",
    "verify_recovery",
    "reset_password",
    "change_email",
    "welcome",
    "existing_account",
]
EMAIL_KINDS: tuple[EmailKind, ...] = get_args(EmailKind)

# Per-target-email throttle actions -> the rate_limits keys they borrow.
VERIFY_ACTION = "email_verify_request"
RESET_ACTION = "password_reset_request"
CHANGE_ACTION = "email_change_request"
EXISTING_ACCOUNT_ACTION = "existing_account_notice"

# Default frontend paths the signed-token links point at.
DEFAULT_VERIFY_PATH = "/verify-email"
DEFAULT_RESET_PATH = "/reset-password"
DEFAULT_CHANGE_PATH = "/confirm-email-change"

# Email subject lines.
SUBJECT_VERIFY = "Verify your email"
SUBJECT_RESET = "Reset your password"
SUBJECT_CHANGE = "Confirm your new email"
SUBJECT_EXISTING_ACCOUNT = "You already have an account"
