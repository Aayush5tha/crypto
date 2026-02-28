from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone


SESSION_HOURS = 12


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hours_from_now_iso(hours: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


def make_salt() -> str:
    return secrets.token_hex(16)


def hash_password(password: str, salt: str) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200000)
    return digest.hex()


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    actual = hash_password(password, salt)
    return hmac.compare_digest(actual, expected_hash)


def make_session_token() -> str:
    return secrets.token_urlsafe(48)
