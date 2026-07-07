"""ORM models — mirror the schema in docs/DEVELOPMENT_PLAN.md §4.

Portable across SQLite/Postgres: UUID PKs stored as TEXT, JSON columns via the
SQLAlchemy-generic JSON type, UTC timestamps.
"""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    Boolean,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base, ts_column, uuid_pk


class Network(Base):
    __tablename__ = "networks"

    id: Mapped[str] = uuid_pk()
    cidr: Mapped[str] = mapped_column(String(64))
    label: Mapped[str | None] = mapped_column(String(128), nullable=True)
    gateway_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    owner_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at = ts_column()

    scans: Mapped[list["Scan"]] = relationship(back_populates="network", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = uuid_pk()
    network_id: Mapped[str | None] = mapped_column(ForeignKey("networks.id"), nullable=True)
    target: Mapped[str] = mapped_column(String(128))
    profile: Mapped[str] = mapped_column(String(32), default="quick")
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued/running/completed/failed/cancelled
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    grade: Mapped[str | None] = mapped_column(String(2), nullable=True)
    started_at = ts_column(nullable=True)
    finished_at = ts_column(nullable=True)
    created_at = ts_column()

    network: Mapped["Network"] = relationship(back_populates="scans")
    job: Mapped["ScanJob"] = relationship(back_populates="scan", uselist=False, cascade="all, delete-orphan")
    devices: Mapped[list["Device"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    recommendations: Mapped[list["Recommendation"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = uuid_pk()
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    status: Mapped[str] = mapped_column(String(16), default="queued")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    current_stage: Mapped[str | None] = mapped_column(String(32), nullable=True)
    heartbeat_at = ts_column(nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="job")


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = uuid_pk()
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    ip: Mapped[str] = mapped_column(String(64))
    mac: Mapped[str | None] = mapped_column(String(32), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    os_family: Mapped[str | None] = mapped_column(String(64), nullable=True)
    os_accuracy: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_up: Mapped[bool] = mapped_column(Boolean, default=True)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    grade: Mapped[str | None] = mapped_column(String(2), nullable=True)
    score_factors: Mapped[list] = mapped_column(JSON, default=list)

    scan: Mapped["Scan"] = relationship(back_populates="devices")
    ports: Mapped[list["Port"]] = relationship(back_populates="device", cascade="all, delete-orphan")


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[str] = uuid_pk()
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"))
    number: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    state: Mapped[str] = mapped_column(String(16), default="open")
    reason: Mapped[str | None] = mapped_column(String(32), nullable=True)

    device: Mapped["Device"] = relationship(back_populates="ports")
    service: Mapped["Service"] = relationship(back_populates="port", uselist=False, cascade="all, delete-orphan")


class Service(Base):
    __tablename__ = "services"

    id: Mapped[str] = uuid_pk()
    port_id: Mapped[str] = mapped_column(ForeignKey("ports.id"))
    name: Mapped[str] = mapped_column(String(64), default="unknown")
    product: Mapped[str | None] = mapped_column(String(128), nullable=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cpe: Mapped[str | None] = mapped_column(String(255), nullable=True)
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)
    extra: Mapped[dict] = mapped_column(JSON, default=dict)

    port: Mapped["Port"] = relationship(back_populates="service")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="service", cascade="all, delete-orphan"
    )


class Cve(Base):
    """Cached CVE catalog rows (shared across scans)."""

    __tablename__ = "cves"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    description: Mapped[str] = mapped_column(Text)
    cvss_v3: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    cwe: Mapped[str | None] = mapped_column(String(32), nullable=True)
    published: Mapped[str | None] = mapped_column(String(32), nullable=True)
    references: Mapped[list] = mapped_column(JSON, default=list)
    fixed_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[str] = uuid_pk()
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"))
    cve_id: Mapped[str] = mapped_column(ForeignKey("cves.id"))
    match_confidence: Mapped[float] = mapped_column(Float, default=1.0)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(16), default="open")  # open/acknowledged/resolved
    detected_at = ts_column()

    scan: Mapped["Scan"] = relationship(back_populates="vulnerabilities")
    service: Mapped["Service"] = relationship(back_populates="vulnerabilities")
    cve: Mapped["Cve"] = relationship()


class Recommendation(Base):
    __tablename__ = "recommendations"

    id: Mapped[str] = uuid_pk()
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    device_id: Mapped[str | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    vulnerability_id: Mapped[str | None] = mapped_column(ForeignKey("vulnerabilities.id"), nullable=True)
    category: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    action: Mapped[str | None] = mapped_column(Text, nullable=True)
    priority: Mapped[int] = mapped_column(Integer, default=3)

    scan: Mapped["Scan"] = relationship(back_populates="recommendations")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = uuid_pk()
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    format: Mapped[str] = mapped_column(String(8))  # pdf/html/json/csv
    file_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at = ts_column()

    scan: Mapped["Scan"] = relationship(back_populates="reports")
