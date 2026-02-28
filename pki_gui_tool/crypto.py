from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID

from .models import CertInfo, DecryptResult, SignatureResult
from .storage import DataStore
from .utils import b64d, b64e, cert_fingerprint_sha256, sha256_hex


def generate_keypair(alg: str, key_size: int = 2048, curve_name: str = "secp256r1"):
    if alg == "RSA":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    elif alg == "ECC":
        curve = {
            "secp256r1": ec.SECP256R1(),
            "secp384r1": ec.SECP384R1(),
            "secp521r1": ec.SECP521R1(),
        }.get(curve_name, ec.SECP256R1())
        private_key = ec.generate_private_key(curve)
    else:
        raise ValueError("Unsupported algorithm")
    return private_key, private_key.public_key()


def build_name(common_name: str, org: str = "", country: str = "") -> x509.Name:
    parts = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if org:
        parts.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    if country:
        parts.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    return x509.Name(parts)


def create_self_signed_cert(private_key, subject_cn: str, days_valid: int = 365):
    subject = build_name(subject_cn)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return cert


def create_csr(private_key, subject_cn: str, org: str = "", country: str = ""):
    subject = build_name(subject_cn, org, country)
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
        private_key, hashes.SHA256()
    )
    return csr


def sign_csr(ca_private_key, ca_cert: x509.Certificate, csr: x509.CertificateSigningRequest, days_valid: int = 365):
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_private_key, hashes.SHA256())
    )
    return cert


def cert_info(cert: x509.Certificate) -> CertInfo:
    return CertInfo(
        subject_cn=cert.subject.rfc4514_string(),
        issuer_cn=cert.issuer.rfc4514_string(),
        serial_number=str(cert.serial_number),
        not_before=cert.not_valid_before.strftime("%Y-%m-%d"),
        not_after=cert.not_valid_after.strftime("%Y-%m-%d"),
        fingerprint_sha256=cert_fingerprint_sha256(cert),
    )


def sign_bytes(private_key, data: bytes) -> bytes:
    if isinstance(private_key, rsa.RSAPrivateKey):
        return private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    raise ValueError("Unsupported key type")


def verify_bytes(public_key, data: bytes, signature: bytes) -> bool:
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        else:
            return False
        return True
    except Exception:
        return False


def sign_file(path: Path, private_key, signer_cert: Optional[x509.Certificate]) -> Dict[str, str]:
    payload = path.read_bytes()
    nonce = sha256_hex(os.urandom(32))
    timestamp = str(int(time.time()))
    meta = {
        "filename": path.name,
        "size": str(len(payload)),
        "sha256": sha256_hex(payload),
        "timestamp": timestamp,
        "nonce": nonce,
    }
    data_to_sign = json.dumps(meta, sort_keys=True).encode("utf-8")
    signature = sign_bytes(private_key, data_to_sign)
    out = {
        "meta": meta,
        "signature": b64e(signature),
        "signer_fingerprint": cert_fingerprint_sha256(signer_cert) if signer_cert else "",
    }
    return out


def verify_file(
    path: Path,
    signature_blob: Dict[str, str],
    public_key,
    store: Optional[DataStore] = None,
    enforce_replay: bool = False,
) -> SignatureResult:
    meta = signature_blob.get("meta", {})
    if not meta:
        return SignatureResult(False, "Missing metadata")
    try:
        sig = b64d(signature_blob.get("signature", ""))
    except Exception:
        return SignatureResult(False, "Invalid signature encoding")
    data_to_verify = json.dumps(meta, sort_keys=True).encode("utf-8")
    nonce = meta.get("nonce", "")
    if enforce_replay:
        if store is None:
            return SignatureResult(False, "Replay enforcement requires a nonce store")
        if not nonce:
            return SignatureResult(False, "Missing nonce")
        if store.has_nonce(nonce):
            return SignatureResult(False, "Replay detected (nonce already seen)")
    ok = verify_bytes(public_key, data_to_verify, sig)
    if not ok:
        return SignatureResult(False, "Signature mismatch")
    actual = sha256_hex(path.read_bytes())
    if actual != meta.get("sha256", ""):
        return SignatureResult(False, "File hash mismatch")
    if enforce_replay:
        store.record_nonce(nonce)
    return SignatureResult(True, "Signature valid", signature_blob.get("signer_fingerprint"))


def hybrid_encrypt_rsa(plaintext: bytes, recipient_public_key) -> Dict[str, str]:
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    wrapped = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return {
        "alg": "RSA-OAEP+AESGCM",
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "wrapped_key": b64e(wrapped),
    }


def hybrid_decrypt_rsa(blob: Dict[str, str], recipient_private_key) -> bytes:
    nonce = b64d(blob["nonce"])
    ciphertext = b64d(blob["ciphertext"])
    wrapped = b64d(blob["wrapped_key"])
    aes_key = recipient_private_key.decrypt(
        wrapped,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def hybrid_encrypt_ecc(plaintext: bytes, recipient_public_key: ec.EllipticCurvePublicKey) -> Dict[str, str]:
    ephemeral_private = ec.generate_private_key(recipient_public_key.curve)
    shared = ephemeral_private.exchange(ec.ECDH(), recipient_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pki-gui-tool",
    ).derive(shared)
    aesgcm = AESGCM(derived_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    epk_bytes = ephemeral_private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "alg": "ECDH+AESGCM",
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "ephemeral_public": b64e(epk_bytes),
    }


def hybrid_decrypt_ecc(blob: Dict[str, str], recipient_private_key: ec.EllipticCurvePrivateKey) -> bytes:
    nonce = b64d(blob["nonce"])
    ciphertext = b64d(blob["ciphertext"])
    epk_bytes = b64d(blob["ephemeral_public"])
    ephemeral_public = serialization.load_pem_public_key(epk_bytes)
    shared = recipient_private_key.exchange(ec.ECDH(), ephemeral_public)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pki-gui-tool",
    ).derive(shared)
    aesgcm = AESGCM(derived_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def encrypt_file(path: Path, recipient_public_key) -> Dict[str, str]:
    plaintext = path.read_bytes()
    if isinstance(recipient_public_key, rsa.RSAPublicKey):
        blob = hybrid_encrypt_rsa(plaintext, recipient_public_key)
    elif isinstance(recipient_public_key, ec.EllipticCurvePublicKey):
        blob = hybrid_encrypt_ecc(plaintext, recipient_public_key)
    else:
        raise ValueError("Unsupported key type")
    blob["filename"] = path.name
    blob["sha256"] = sha256_hex(plaintext)
    return blob


def decrypt_file(blob: Dict[str, str], recipient_private_key, output_path: Path) -> DecryptResult:
    try:
        if blob.get("alg") == "RSA-OAEP+AESGCM":
            plaintext = hybrid_decrypt_rsa(blob, recipient_private_key)
        elif blob.get("alg") == "ECDH+AESGCM":
            plaintext = hybrid_decrypt_ecc(blob, recipient_private_key)
        else:
            return DecryptResult(False, "Unsupported encryption algorithm")
        if sha256_hex(plaintext) != blob.get("sha256", ""):
            return DecryptResult(False, "Integrity check failed")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(plaintext)
        return DecryptResult(True, "Decrypted OK", str(output_path))
    except Exception as exc:
        return DecryptResult(False, f"Decrypt failed: {exc}")
