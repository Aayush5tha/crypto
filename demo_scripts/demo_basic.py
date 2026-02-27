from pathlib import Path

from pki_gui_tool import crypto
from pki_gui_tool.storage import DataStore

base = Path(__file__).resolve().parents[1] / "data" / "demo"
base.mkdir(parents=True, exist_ok=True)
store = DataStore(base)

# Generate keys
priv, pub = crypto.generate_keypair("RSA", 2048, "secp256r1")

# Encrypt/decrypt demo
plain = base / "message.txt"
plain.write_text("Confidential report")
enc = crypto.encrypt_file(plain, pub)
(out := base / "encrypted.json").write_text(__import__("json").dumps(enc, indent=2))
result = crypto.decrypt_file(enc, priv, base / "decrypted.txt")
print("Decrypt result:", result.reason)

# Sign/verify demo
sig = crypto.sign_file(plain, priv, None, store)
(base / "signature.json").write_text(__import__("json").dumps(sig, indent=2))
verify = crypto.verify_file(plain, sig, pub, store)
print("Verify result:", verify.reason)
