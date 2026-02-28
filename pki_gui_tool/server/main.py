from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import Depends, FastAPI, Header, HTTPException
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .database import db
from .schemas import (
    AuthResponse,
    CertRecordResponse,
    CertRevokeRequest,
    CertUploadRequest,
    LoginRequest,
    MeResponse,
    MessageResponse,
    RegisterRequest,
    RevokeStatusResponse,
)
from .security import (
    SESSION_HOURS,
    hash_password,
    hours_from_now_iso,
    make_salt,
    make_session_token,
    now_iso,
    parse_iso,
    verify_password,
)


app = FastAPI(title="PKI Forge Multi-User API", version="1.0.0")


def _audit(conn, actor_user_id: int | None, action: str, details: str = "") -> None:
    conn.execute(
        "INSERT INTO audit_logs(actor_user_id, action, details, created_at) VALUES (?, ?, ?, ?)",
        (actor_user_id, action, details, now_iso()),
    )


def _get_user_by_username(conn, username: str):
    return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def _get_user_by_id(conn, user_id: int):
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def _auth_header_to_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authorization must be Bearer <token>")
    return parts[1].strip()


def _session_to_user(token: str):
    with db.connect() as conn:
        session = conn.execute("SELECT * FROM sessions WHERE token = ?", (token,)).fetchone()
        if session is None:
            raise HTTPException(status_code=401, detail="Invalid session")
        if parse_iso(session["expires_at"]) <= datetime.now(timezone.utc):
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            raise HTTPException(status_code=401, detail="Session expired")
        user = _get_user_by_id(conn, int(session["user_id"]))
        if user is None:
            raise HTTPException(status_code=401, detail="Session user not found")
        return user, session


def require_user(authorization: str | None = Header(default=None)):
    token = _auth_header_to_token(authorization)
    user, _ = _session_to_user(token)
    return user


@app.get("/health", response_model=MessageResponse)
def health():
    return MessageResponse(message="ok")


@app.post("/auth/register", response_model=MessageResponse)
def register(payload: RegisterRequest):
    role = payload.role.lower().strip()
    if role not in {"user", "admin"}:
        raise HTTPException(status_code=400, detail="Role must be 'user' or 'admin'")

    username = payload.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")

    with db.connect() as conn:
        existing = _get_user_by_username(conn, username)
        if existing is not None:
            raise HTTPException(status_code=409, detail="Username already exists")

        # First user is always admin, regardless of requested role.
        total_users = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
        if int(total_users) == 0:
            role = "admin"

        salt = make_salt()
        pw_hash = hash_password(payload.password, salt)
        conn.execute(
            "INSERT INTO users(username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (username, pw_hash, salt, role, now_iso()),
        )
        user = _get_user_by_username(conn, username)
        _audit(conn, int(user["id"]), "register", f"role={role}")
    return MessageResponse(message=f"User '{username}' registered")


@app.post("/auth/login", response_model=AuthResponse)
def login(payload: LoginRequest):
    username = payload.username.strip()
    with db.connect() as conn:
        user = _get_user_by_username(conn, username)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid username or password")

        if not verify_password(payload.password, user["salt"], user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid username or password")

        token = make_session_token()
        created_at = now_iso()
        expires_at = hours_from_now_iso(SESSION_HOURS)
        conn.execute(
            "INSERT INTO sessions(token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, int(user["id"]), created_at, expires_at),
        )
        _audit(conn, int(user["id"]), "login", "")

    return AuthResponse(token=token, username=user["username"], role=user["role"], expires_at=expires_at)


@app.post("/auth/logout", response_model=MessageResponse)
def logout(authorization: str | None = Header(default=None)):
    token = _auth_header_to_token(authorization)
    with db.connect() as conn:
        session = conn.execute("SELECT * FROM sessions WHERE token = ?", (token,)).fetchone()
        if session is not None:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            _audit(conn, int(session["user_id"]), "logout", "")
    return MessageResponse(message="Logged out")


@app.get("/auth/me", response_model=MeResponse)
def me(user=Depends(require_user)):
    return MeResponse(id=int(user["id"]), username=user["username"], role=user["role"])


@app.post("/certificates/upload", response_model=CertRecordResponse)
def upload_certificate(payload: CertUploadRequest, user=Depends(require_user)):
    try:
        cert = x509.load_pem_x509_certificate(payload.cert_pem.encode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid certificate PEM: {exc}")

    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    serial = str(cert.serial_number)

    with db.connect() as conn:
        existing = conn.execute("SELECT * FROM certificates WHERE fingerprint = ?", (fingerprint,)).fetchone()
        if existing is not None:
            owner = _get_user_by_id(conn, int(existing["owner_id"]))
            return CertRecordResponse(
                id=int(existing["id"]),
                owner=owner["username"] if owner else "unknown",
                subject=existing["subject"],
                issuer=existing["issuer"],
                serial=existing["serial"],
                fingerprint=existing["fingerprint"],
                revoked=bool(existing["revoked"]),
                revocation_reason=existing["revocation_reason"],
                created_at=existing["created_at"],
            )

        conn.execute(
            """
            INSERT INTO certificates(
                owner_id, subject, issuer, serial, fingerprint, pem, revoked, revocation_reason, revoked_at, revoked_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, 0, NULL, NULL, NULL, ?)
            """,
            (
                int(user["id"]),
                subject,
                issuer,
                serial,
                fingerprint,
                payload.cert_pem,
                now_iso(),
            ),
        )
        row = conn.execute("SELECT * FROM certificates WHERE fingerprint = ?", (fingerprint,)).fetchone()
        _audit(conn, int(user["id"]), "upload_certificate", f"fingerprint={fingerprint}")

    return CertRecordResponse(
        id=int(row["id"]),
        owner=user["username"],
        subject=row["subject"],
        issuer=row["issuer"],
        serial=row["serial"],
        fingerprint=row["fingerprint"],
        revoked=bool(row["revoked"]),
        revocation_reason=row["revocation_reason"],
        created_at=row["created_at"],
    )


@app.get("/certificates", response_model=List[CertRecordResponse])
def list_certificates(user=Depends(require_user)):
    with db.connect() as conn:
        rows = conn.execute(
            """
            SELECT c.*, u.username AS owner_name
            FROM certificates c
            LEFT JOIN users u ON u.id = c.owner_id
            ORDER BY c.id DESC
            """
        ).fetchall()

    return [
        CertRecordResponse(
            id=int(r["id"]),
            owner=r["owner_name"] or "unknown",
            subject=r["subject"],
            issuer=r["issuer"],
            serial=r["serial"],
            fingerprint=r["fingerprint"],
            revoked=bool(r["revoked"]),
            revocation_reason=r["revocation_reason"],
            created_at=r["created_at"],
        )
        for r in rows
    ]


@app.get("/certificates/revoked/{fingerprint}", response_model=RevokeStatusResponse)
def revocation_status(fingerprint: str, user=Depends(require_user)):
    with db.connect() as conn:
        cert = conn.execute("SELECT * FROM certificates WHERE fingerprint = ?", (fingerprint,)).fetchone()
    if cert is None:
        return RevokeStatusResponse(fingerprint=fingerprint, revoked=False, revocation_reason=None)
    return RevokeStatusResponse(
        fingerprint=fingerprint,
        revoked=bool(cert["revoked"]),
        revocation_reason=cert["revocation_reason"],
    )


@app.post("/certificates/revoke", response_model=MessageResponse)
def revoke_certificate(payload: CertRevokeRequest, user=Depends(require_user)):
    fingerprint = payload.fingerprint.strip().lower()
    if not fingerprint:
        raise HTTPException(status_code=400, detail="Fingerprint is required")

    with db.connect() as conn:
        cert = conn.execute("SELECT * FROM certificates WHERE fingerprint = ?", (fingerprint,)).fetchone()
        if cert is None:
            raise HTTPException(status_code=404, detail="Certificate not found in registry")

        is_admin = user["role"] == "admin"
        is_owner = int(cert["owner_id"]) == int(user["id"])
        if not (is_admin or is_owner):
            raise HTTPException(status_code=403, detail="Only admin or certificate owner can revoke")

        if bool(cert["revoked"]):
            return MessageResponse(message="Certificate already revoked")

        conn.execute(
            """
            UPDATE certificates
            SET revoked = 1, revocation_reason = ?, revoked_at = ?, revoked_by = ?
            WHERE fingerprint = ?
            """,
            (payload.reason.strip() or "Unspecified", now_iso(), int(user["id"]), fingerprint),
        )
        _audit(conn, int(user["id"]), "revoke_certificate", f"fingerprint={fingerprint}")

    return MessageResponse(message="Certificate revoked")
