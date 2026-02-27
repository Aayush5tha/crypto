# PKI Forge - GUI Cryptography Tool

A polished, GUI-based cryptographic tool that demonstrates PKI workflows, digital signatures, hybrid encryption, secure key storage, and attack simulations. Built for the ST6051CEM Practical Cryptography coursework.

## Features
- Key and certificate management (RSA/ECC)
- Self-signed certs, CSR creation, CA signing
- Digital signatures with replay protection (nonce cache)
- Hybrid encryption (RSA-OAEP+AES-GCM, ECDH+AES-GCM)
- Password-protected keystore (PKCS#12)
- Certificate revocation list (CRL)
- MITM and replay attack simulations
- GUI-first workflow and clear logging

## Quick Start
```powershell
cd C:\Users\denis\.vscode\python\pki_gui_tool
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

## Usage Notes
- All generated artifacts are stored in `data/output` by default, but you can change this in the GUI.
- The signature file is a JSON structure containing metadata, file hash, and a replay-resistant nonce.
- Verification checks: signature correctness, file integrity, and replay detection.
- Encryption outputs a JSON package (encrypted content + key wrapping / ephemeral key).

## Use Cases (Examples)
1. **Secure document signing for academic submissions**
   - Sign PDFs or documents. Verification ensures integrity and authenticity.
2. **Encrypted file transfer between departments**
   - Hybrid encryption for secure exchange using a recipient’s public key.
3. **Device-to-device trust bootstrap**
   - Generate CSRs, issue certs with a local CA, and revoke compromised keys.

## Testing
```powershell
pytest -q
```

## Project Structure
- `app.py` - entrypoint for the GUI
- `pki_gui_tool/gui.py` - user interface
- `pki_gui_tool/crypto.py` - cryptographic primitives and workflows
- `pki_gui_tool/storage.py` - keystore, CRL, nonce cache
- `pki_gui_tool/attacks.py` - MITM and replay simulations
- `tests/` - unit tests

## Security Notes
- Private keys can be stored encrypted (PKCS#12) with a password.
- Replay detection is enforced via nonce cache.
- MITM simulation is based on certificate fingerprint mismatch.

## License
MIT (add a LICENSE file if you want to publish the repository).
