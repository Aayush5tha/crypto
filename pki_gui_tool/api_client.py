from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests


class APIClientError(Exception):
    pass


@dataclass
class SessionInfo:
    token: str
    username: str
    role: str
    expires_at: str


class APIClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8765"):
        self.base_url = base_url.rstrip("/")
        self._session: Optional[SessionInfo] = None

    @property
    def is_authenticated(self) -> bool:
        return self._session is not None

    @property
    def session(self) -> Optional[SessionInfo]:
        return self._session

    def set_base_url(self, url: str) -> None:
        self.base_url = url.rstrip("/")

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._session is not None:
            headers["Authorization"] = f"Bearer {self._session.token}"
        return headers

    def _request(self, method: str, path: str, json_body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        try:
            resp = requests.request(method, url, json=json_body, headers=self._headers(), timeout=10)
        except Exception as exc:
            raise APIClientError(f"Server unreachable: {exc}")
        try:
            data = resp.json() if resp.text else {}
        except Exception:
            data = {"detail": resp.text}
        if resp.status_code >= 400:
            detail = data.get("detail") if isinstance(data, dict) else str(data)
            raise APIClientError(f"{resp.status_code}: {detail}")
        return data if isinstance(data, dict) else {}

    def health(self) -> str:
        data = self._request("GET", "/health")
        return str(data.get("message", ""))

    def register(self, username: str, password: str, role: str = "user") -> str:
        data = self._request("POST", "/auth/register", {"username": username, "password": password, "role": role})
        return str(data.get("message", "Registered"))

    def login(self, username: str, password: str) -> SessionInfo:
        data = self._request("POST", "/auth/login", {"username": username, "password": password})
        session = SessionInfo(
            token=str(data["token"]),
            username=str(data["username"]),
            role=str(data["role"]),
            expires_at=str(data["expires_at"]),
        )
        self._session = session
        return session

    def logout(self) -> str:
        if not self._session:
            return "Already logged out"
        data = self._request("POST", "/auth/logout")
        self._session = None
        return str(data.get("message", "Logged out"))

    def me(self) -> Dict[str, Any]:
        return self._request("GET", "/auth/me")

    def upload_certificate(self, cert_pem: str) -> Dict[str, Any]:
        return self._request("POST", "/certificates/upload", {"cert_pem": cert_pem})

    def list_certificates(self) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/certificates"
        try:
            resp = requests.get(url, headers=self._headers(), timeout=10)
        except Exception as exc:
            raise APIClientError(f"Server unreachable: {exc}")
        try:
            data = resp.json() if resp.text else []
        except Exception:
            data = []
        if resp.status_code >= 400:
            detail = data.get("detail") if isinstance(data, dict) else str(data)
            raise APIClientError(f"{resp.status_code}: {detail}")
        return data if isinstance(data, list) else []

    def revocation_status(self, fingerprint: str) -> Dict[str, Any]:
        return self._request("GET", f"/certificates/revoked/{fingerprint}")

    def revoke_certificate(self, fingerprint: str, reason: str) -> str:
        data = self._request("POST", "/certificates/revoke", {"fingerprint": fingerprint, "reason": reason})
        return str(data.get("message", "Certificate revoked"))
