from pathlib import Path
import tempfile

from cryptography.hazmat.primitives.asymmetric import ec

from pki_gui_tool import crypto
from pki_gui_tool.storage import DataStore


def test_sign_verify_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        store = DataStore(base)
        priv, pub = crypto.generate_keypair("RSA", 2048, "secp256r1")
        data_path = base / "data.txt"
        data_path.write_text("hello")
        blob = crypto.sign_file(data_path, priv, None, store)
        result = crypto.verify_file(data_path, blob, pub, store)
        assert result.ok


def test_encrypt_decrypt_rsa():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        priv, pub = crypto.generate_keypair("RSA", 2048, "secp256r1")
        data_path = base / "msg.txt"
        data_path.write_text("secret")
        blob = crypto.encrypt_file(data_path, pub)
        out_path = base / "out.txt"
        result = crypto.decrypt_file(blob, priv, out_path)
        assert result.ok
        assert out_path.read_text() == "secret"


def test_encrypt_decrypt_ecc():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        priv, pub = crypto.generate_keypair("ECC", 2048, "secp256r1")
        data_path = base / "msg.txt"
        data_path.write_text("secret")
        blob = crypto.encrypt_file(data_path, pub)
        out_path = base / "out.txt"
        result = crypto.decrypt_file(blob, priv, out_path)
        assert result.ok
        assert out_path.read_text() == "secret"


def test_verify_handles_invalid_base64_signature():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        store = DataStore(base)
        priv, pub = crypto.generate_keypair("RSA", 2048, "secp256r1")
        data_path = base / "data.txt"
        data_path.write_text("hello")
        blob = crypto.sign_file(data_path, priv, None, store)
        blob["signature"] = "not-base64-@@@"
        result = crypto.verify_file(data_path, blob, pub, store)
        assert not result.ok
        assert "Invalid signature encoding" in result.reason
