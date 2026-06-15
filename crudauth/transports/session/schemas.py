"""Pydantic shapes for server-side sessions and CSRF tokens."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

__all__ = ["SessionData", "CSRFToken", "UserAgentInfo"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UserAgentInfo(BaseModel):
    browser: str = "Unknown"
    browser_version: str = ""
    os: str = "Unknown"
    device: str = "Unknown"
    is_mobile: bool = False
    is_tablet: bool = False
    is_pc: bool = False


class SessionData(BaseModel):
    user_id: Any
    session_id: str = Field(default_factory=lambda: str(uuid4()))
    ip_address: str = ""
    user_agent: str = ""
    device_info: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_utcnow)
    last_activity: datetime = Field(default_factory=_utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CSRFToken(BaseModel):
    token: str
    user_id: Any
    session_id: str
    expiry: datetime
