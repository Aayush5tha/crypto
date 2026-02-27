from __future__ import annotations

from typing import Dict

from cryptography import x509

from .storage import DataStore
from .utils import cert_fingerprint_sha256


def simulate_mitm(expected_cert: x509.Certificate, presented_cert: x509.Certificate) -> Dict[str, str]:
    expected_fp = cert_fingerprint_sha256(expected_cert)
    presented_fp = cert_fingerprint_sha256(presented_cert)
    if expected_fp != presented_fp:
        return {
            "ok": "false",
            "result": "MITM detected: certificate fingerprint mismatch",
            "expected_fingerprint": expected_fp,
            "presented_fingerprint": presented_fp,
        }
    return {"ok": "true", "result": "No MITM detected"}


def simulate_replay(store: DataStore, nonce: str) -> Dict[str, str]:
    if store.has_nonce(nonce):
        return {"ok": "false", "result": "Replay detected: nonce already seen"}
    store.record_nonce(nonce)
    return {"ok": "true", "result": "No replay detected"}
