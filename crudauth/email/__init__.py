"""Email flows: the package mints/verifies signed tokens; you own delivery."""

from __future__ import annotations

from .channel import DeliveryChannel, DeliveryIntent, DeliveryKind, EmailChannel
from .config import EmailConfig
from .sender import EmailContext, EmailSender
from .service import EmailFlowService

__all__ = [
    "EmailSender",
    "EmailContext",
    "EmailConfig",
    "EmailFlowService",
    "DeliveryChannel",
    "DeliveryIntent",
    "DeliveryKind",
    "EmailChannel",
]
