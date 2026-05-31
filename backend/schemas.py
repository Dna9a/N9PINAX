# backend/schemas.py
# Request / response models for the public API.

from __future__ import annotations

import ipaddress
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class ScanRequest(BaseModel):
    """Body of POST /api/scan."""

    network: Optional[str] = Field(
        None,
        max_length=43,  # max CIDR string length (IPv6/64)
        description="CIDR range (e.g. 192.168.1.0/24). Auto-detected when null.",
    )
    udp: bool = Field(False, description="Include UDP probes.")
    dhcp: bool = Field(False, description="Run passive DHCP fingerprinting.")
    resolve_hostnames: bool = Field(True, description="Run reverse-DNS lookups.")

    @field_validator("network")
    @classmethod
    def _validate_network(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        if not v:
            return None
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR network: {e}")
        return v


class ScanJobResponse(BaseModel):
    """Returned by POST /api/scan."""

    job_id: str
    network: str
    status: str
    started_at: Optional[str] = None
    scan_id: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    version: str
    uptime_seconds: float


class NoteCreate(BaseModel):
    """Body of POST /api/notes."""

    title: str = Field("Untitled", max_length=200)
    content: str = Field("", max_length=50_000)
    scan_id: Optional[str] = Field(None, max_length=36)
    device_ip: Optional[str] = Field(None, max_length=45)
    tags: list[str] = Field(default_factory=list)


class NoteUpdate(BaseModel):
    """Body of PATCH /api/notes/{note_id}. Only provided fields are updated."""

    title: Optional[str] = Field(None, max_length=200)
    content: Optional[str] = Field(None, max_length=50_000)
    tags: Optional[list[str]] = None
    scan_id: Optional[str] = Field(None, max_length=36)
    device_ip: Optional[str] = Field(None, max_length=45)
