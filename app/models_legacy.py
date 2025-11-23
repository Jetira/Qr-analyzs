"""
SQLAlchemy ORM models for QR Security Service.

Defines database tables:
- Station: EV charging stations
- QRScan: Records of QR code scans and analysis results
- DomainReputation: Known safe/malicious domains database
"""

import uuid
from datetime import datetime
from typing import List

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Station(Base):
    """
    EV Charging Station model.
    
    Represents a physical charging station that may have QR codes.
    Used to track which station's QR code was scanned.
    """
    __tablename__ = "stations"
    
    # Primary key (UUID for distributed systems and better security)
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Unique station identifier"
    )
    
    # Station identification
    station_code: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
        comment="Human-readable station code (e.g. 'CP-001')"
    )
    
    # Station metadata
    location: Mapped[str] = mapped_column(
        String(255),
        nullable=True,
        comment="Physical location of the station"
    )
    
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        comment="Whether the station is currently active"
    )
    
    # Relationships
    qr_scans: Mapped[List["QRScan"]] = relationship(
        "QRScan",
        back_populates="station",
        cascade="all, delete-orphan"
    )
    
    def __repr__(self) -> str:
        return f"<Station(code={self.station_code}, location={self.location})>"


class QRScan(Base):
    """
    QR Code Scan Record.
    
    Stores every QR code scan attempt with full analysis results.
    This provides audit trail and helps detect patterns of attacks.
    
    Security importance:
    - Audit logging for forensic analysis
    - Pattern detection (e.g., multiple scans of same malicious QR)
    - Incident response data
    """
    __tablename__ = "qr_scans"
    
    # Primary key
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Unique scan identifier"
    )
    
    # Foreign key to station (nullable because QR might be from unknown location)
    station_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("stations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Station where QR was scanned (if known)"
    )
    
    # QR data and parsed information
    raw_qr_data: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Raw QR code content as scanned"
    )
    
    parsed_url: Mapped[str] = mapped_column(
        Text,
        nullable=True,
        comment="Normalized URL extracted from QR (if applicable)"
    )
    
    host: Mapped[str] = mapped_column(
        String(255),
        nullable=True,
        index=True,
        comment="Hostname from the URL for quick filtering"
    )
    
    # Analysis results
    verdict: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
        comment="Risk verdict: 'safe', 'suspicious', or 'malicious'"
    )
    
    score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Risk score (0-100, higher = more dangerous)"
    )
    
    # Reasons for the verdict (stored as JSON array)
    # Example: ["HTTPS değil", "Resmi domain değil", "APK indirme tespit edildi"]
    # Using JSON instead of JSONB for SQLite compatibility
    reasons: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment="List of security issues detected (JSON array)"
    )
    
    # Client information (for analytics and debugging)
    app_version: Mapped[str] = mapped_column(
        String(50),
        nullable=True,
        comment="Mobile app version that performed the scan"
    )
    
    platform: Mapped[str] = mapped_column(
        String(20),
        nullable=True,
        comment="Client platform: 'android', 'ios', etc."
    )
    
    # Timestamp
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
        comment="When the scan occurred"
    )
    
    # Relationships
    station: Mapped["Station"] = relationship(
        "Station",
        back_populates="qr_scans"
    )
    
    def __repr__(self) -> str:
        return f"<QRScan(id={self.id}, verdict={self.verdict}, score={self.score})>"


class DomainReputation(Base):
    """
    Domain Reputation Database.
    
    Maintains allowlist (official domains) and denylist (known malicious domains).
    
    Security importance:
    - Official domains get low risk scores automatically
    - Denied domains get high risk scores (known phishing/malware sites)
    - Supports dynamic updates without code changes
    - Can be populated from threat intelligence feeds
    """
    __tablename__ = "domain_reputation"
    
    # Primary key
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True
    )
    
    # Domain name
    host: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="Domain name (e.g., 'example.com')"
    )
    
    # Reputation flags
    is_official: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="True if this is an official/trusted domain"
    )
    
    is_denied: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="True if this is a known malicious domain"
    )
    
    # Additional information
    note: Mapped[str] = mapped_column(
        Text,
        nullable=True,
        comment="Notes about this domain (e.g., source of information)"
    )
    
    def __repr__(self) -> str:
        status = "OFFICIAL" if self.is_official else ("DENIED" if self.is_denied else "UNKNOWN")
        return f"<DomainReputation(host={self.host}, status={status})>"
