from __future__ import annotations

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=256)
    role: str = Field(default="user")


class LoginRequest(BaseModel):
    username: str
    password: str


class AuthResponse(BaseModel):
    token: str
    username: str
    role: str
    expires_at: str


class MessageResponse(BaseModel):
    message: str


class CertUploadRequest(BaseModel):
    cert_pem: str


class CertRevokeRequest(BaseModel):
    fingerprint: str
    reason: str = Field(default="Unspecified", max_length=256)


class CertRecordResponse(BaseModel):
    id: int
    owner: str
    subject: str
    issuer: str
    serial: str
    fingerprint: str
    revoked: bool
    revocation_reason: str | None
    created_at: str


class RevokeStatusResponse(BaseModel):
    fingerprint: str
    revoked: bool
    revocation_reason: str | None


class MeResponse(BaseModel):
    id: int
    username: str
    role: str
