from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class CertInfo:
    subject_cn: str
    issuer_cn: str
    serial_number: str
    not_before: str
    not_after: str
    fingerprint_sha256: str


@dataclass
class SignatureResult:
    ok: bool
    reason: str
    signer_fingerprint: Optional[str] = None


@dataclass
class DecryptResult:
    ok: bool
    reason: str
    plaintext_path: Optional[str] = None
