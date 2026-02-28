from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pki_gui_tool import crypto
from pki_gui_tool.server.database import Database
import pki_gui_tool.server.main as server_main


@pytest.fixture
def client(tmp_path, monkeypatch):
    test_db = Database(tmp_path / "test_pki.db")
    monkeypatch.setattr(server_main, "db", test_db)
    return TestClient(server_main.app)


def _make_cert_pem() -> str:
    private_key, _ = crypto.generate_keypair("RSA", 2048, "secp256r1")
    cert = crypto.create_self_signed_cert(private_key, "test-user", 365)
    from cryptography.hazmat.primitives import serialization

    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def test_register_login_and_me(client):
    reg = client.post("/auth/register", json={"username": "alice", "password": "password123", "role": "user"})
    assert reg.status_code == 200

    login = client.post("/auth/login", json={"username": "alice", "password": "password123"})
    assert login.status_code == 200
    token = login.json()["token"]

    me = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["username"] == "alice"


def test_upload_and_revoke_certificate(client):
    client.post("/auth/register", json={"username": "owner", "password": "password123", "role": "user"})
    login = client.post("/auth/login", json={"username": "owner", "password": "password123"})
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    cert_pem = _make_cert_pem()
    upload = client.post("/certificates/upload", json={"cert_pem": cert_pem}, headers=headers)
    assert upload.status_code == 200
    fingerprint = upload.json()["fingerprint"]

    status1 = client.get(f"/certificates/revoked/{fingerprint}", headers=headers)
    assert status1.status_code == 200
    assert status1.json()["revoked"] is False

    revoke = client.post(
        "/certificates/revoke",
        json={"fingerprint": fingerprint, "reason": "key compromise"},
        headers=headers,
    )
    assert revoke.status_code == 200

    status2 = client.get(f"/certificates/revoked/{fingerprint}", headers=headers)
    assert status2.status_code == 200
    assert status2.json()["revoked"] is True
