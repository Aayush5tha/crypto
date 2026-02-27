from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from .utils import read_json, write_json


class DataStore:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.crl_path = base_dir / "crl.json"
        self.nonce_path = base_dir / "nonce_cache.json"

    def add_revoked(self, fingerprint_hex: str, reason: str) -> None:
        data = read_json(self.crl_path)
        revoked = data.get("revoked", {})
        revoked[fingerprint_hex] = {"reason": reason}
        data["revoked"] = revoked
        write_json(self.crl_path, data)

    def is_revoked(self, fingerprint_hex: str) -> bool:
        data = read_json(self.crl_path)
        revoked = data.get("revoked", {})
        return fingerprint_hex in revoked

    def record_nonce(self, nonce: str) -> None:
        data = read_json(self.nonce_path)
        seen = data.get("seen", {})
        seen[nonce] = True
        data["seen"] = seen
        write_json(self.nonce_path, data)

    def has_nonce(self, nonce: str) -> bool:
        data = read_json(self.nonce_path)
        seen = data.get("seen", {})
        return nonce in seen


class KeyStore:
    def __init__(self, path: Path):
        self.path = path

    def save_pkcs12(self, private_key, certificate: x509.Certificate, password: str, name: str) -> None:
        data = pkcs12.serialize_key_and_certificates(
            name.encode("utf-8"),
            private_key,
            certificate,
            None,
            serialization.BestAvailableEncryption(password.encode("utf-8")),
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(data)

    def load_pkcs12(self, password: str):
        data = self.path.read_bytes()
        private_key, certificate, _ = pkcs12.load_key_and_certificates(
            data, password.encode("utf-8")
        )
        return private_key, certificate


def save_private_key_pem(path: Path, private_key, password: Optional[str]) -> None:
    enc = (
        serialization.BestAvailableEncryption(password.encode("utf-8"))
        if password
        else serialization.NoEncryption()
    )
    data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def save_public_key_pem(path: Path, public_key) -> None:
    data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def save_cert_pem(path: Path, cert: x509.Certificate) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def load_cert_pem(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def load_public_key(path: Path):
    return serialization.load_pem_public_key(path.read_bytes())


def load_private_key(path: Path, password: Optional[str]):
    return serialization.load_pem_private_key(
        path.read_bytes(), password=password.encode("utf-8") if password else None
    )
