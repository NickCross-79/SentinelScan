"""Pydantic request/response models for the API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ScanCreate(BaseModel):
    target: str = Field(..., examples=["192.168.1.0/24", "127.0.0.1"])
    profile: str = Field("quick", examples=["quick", "full", "custom"])
    authorized: bool = Field(False, description="User confirms authorization to scan the target")
    options: dict = Field(default_factory=dict, description="e.g. {'ports': [22, 80, 443]}")


class ScanCreated(BaseModel):
    scan_id: str
    status: str


class JobView(BaseModel):
    status: str
    progress: int
    current_stage: str | None = None
    error: str | None = None


class ScanSummary(BaseModel):
    id: str
    target: str
    profile: str
    status: str
    score: int | None = None
    grade: str | None = None
    device_count: int = 0
    vuln_count: int = 0
    critical_count: int = 0
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime
    job: JobView | None = None


class ServiceView(BaseModel):
    name: str
    product: str | None = None
    version: str | None = None
    cpe: str | None = None
    banner: str | None = None


class PortView(BaseModel):
    number: int
    protocol: str
    state: str
    service: ServiceView | None = None


class DeviceSummary(BaseModel):
    id: str
    ip: str
    hostname: str | None = None
    vendor: str | None = None
    os_family: str | None = None
    risk_score: int | None = None
    grade: str | None = None
    open_ports: int = 0


class DeviceDetail(DeviceSummary):
    mac: str | None = None
    os_accuracy: int | None = None
    score_factors: list[dict] = Field(default_factory=list)
    ports: list[PortView] = Field(default_factory=list)


class VulnerabilityView(BaseModel):
    id: str
    cve_id: str
    severity: str
    cvss_v3: float | None = None
    description: str
    device_ip: str | None = None
    port: int | None = None
    product: str | None = None
    version: str | None = None
    match_confidence: float
    false_positive: bool
    status: str
    recommendation: str | None = None
    references: list[str] = Field(default_factory=list)


class VulnerabilityUpdate(BaseModel):
    false_positive: bool | None = None
    status: str | None = None


class RecommendationView(BaseModel):
    id: str
    category: str
    severity: str
    title: str
    description: str | None = None
    action: str | None = None
    priority: int
    device_ip: str | None = None


class ReportCreate(BaseModel):
    scan_id: str
    format: str = Field("json", examples=["json", "html", "csv"])


class ReportView(BaseModel):
    id: str
    scan_id: str
    format: str
    created_at: datetime
    summary: dict = Field(default_factory=dict)
    download_url: str
