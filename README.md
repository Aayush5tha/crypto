# PKI Forge - Multi-User Cryptography Tool

PKI Forge is a GUI cryptography tool with a shared multi-user backend.
It supports authenticated users, certificate registry, server-side revocation, and PKI workflows.

## Features
- Multi-user accounts with login sessions (server-backed)
- Role-aware certificate revocation (owner/admin)
- Shared certificate registry for all users
- Key/certificate management (RSA/ECC)
- CSR generation and CA signing
- Digital signatures and verification
- Hybrid encryption (RSA-OAEP+AES-GCM, ECDH+AES-GCM)
- Password-protected keystore (PKCS#12)
- MITM and replay simulations

## Quick Start
```powershell
cd C:\Users\denis\.vscode\python\pki_gui_tool
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

### 1. Start backend API
```powershell
python server.py
```

### 2. Start GUI
Open a second terminal:
```powershell
cd C:\Users\denis\.vscode\python\pki_gui_tool
.\.venv\Scripts\activate
python app.py
```

## Multi-User Flow
1. In GUI header, verify server URL (default `http://127.0.0.1:8765`) and click `Connect`.
2. Click `Register` to create users.
3. Click `Login` to start a session.
4. Certificate revocation in `Keys & Certs` uses shared server state.
5. Signature verification checks revocation against server when logged in.

## Testing
```powershell
pytest -q
```

## Project Structure
- `app.py` - GUI entrypoint
- `server.py` - backend entrypoint (FastAPI/uvicorn)
- `pki_gui_tool/gui.py` - desktop GUI
- `pki_gui_tool/api_client.py` - GUI API client
- `pki_gui_tool/server/main.py` - API routes/auth logic
- `pki_gui_tool/server/database.py` - SQLite schema/init
- `pki_gui_tool/crypto.py` - cryptographic workflows
- `tests/test_crypto.py` - crypto tests
- `tests/test_server.py` - backend API tests

## Notes
- The first registered user is automatically assigned `admin` role.
- Revocation requires login and is enforced server-side in multi-user mode.
- Local demo/test artifacts are stored under `data/`.
- If port `8765` is blocked, run the server on another port:
```powershell
$env:PKI_SERVER_PORT="9000"
python server.py
```
