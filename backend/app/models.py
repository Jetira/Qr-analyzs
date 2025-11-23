"""
SQLAlchemy ORM models for QR Security Service.

Database schema includes:
- Station: EV charging station information
- QRScan: Audit log of all QR code scans and analysis results
- DomainReputation: Allowlist/denylist for domain validation
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    JSON,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base


class Station(Base):
    """
    EV charging station model.
    
    Represents physical charging stations where QR codes are displayed.
    Used to track which stations are experiencing security issues.
    """
    __tablename__ = "stations"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    station_code = Column(String(50), unique=True, nullable=False, index=True)
    location = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationship to QR scans
    scans = relationship("QRScan", back_populates="station")
    
    def __repr__(self) -> str:
        return f"<Station(code={self.station_code}, location={self.location})>"


class QRScan(Base):
    """
    QR code scan audit log.
    
    Every QR code analysis is logged here for security forensics.
    Critical for investigating phishing campaigns and identifying compromised stations.
    
    Security Considerations:
    - Stores raw QR data (evidence preservation)
    - Captures device context (app_version, platform)
    - Records full analysis verdict and reasoning
    - Immutable audit trail (no updates/deletes in production)
    """
    __tablename__ = "qr_scans"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    station_id = Column(UUID(as_uuid=True), ForeignKey("stations.id"), nullable=True, index=True)
    
    # QR content
    raw_qr_data = Column(Text, nullable=False)
    parsed_url = Column(Text, nullable=True)
    host = Column(String(255), nullable=True, index=True)
    
    # Analysis results
    verdict = Column(String(20), nullable=False, index=True)  # safe, suspicious, malicious
    score = Column(Integer, nullable=False)  # 0-100 risk score
    reasons = Column(JSON, nullable=False)  # List of human-readable explanations
    
    # Device context
    app_version = Column(String(50), nullable=True)
    platform = Column(String(20), nullable=True)  # android, ios
    
    # Audit timestamp
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationship
    station = relationship("Station", back_populates="scans")
    
    def __repr__(self) -> str:
        return f"<QRScan(id={self.id}, verdict={self.verdict}, score={self.score})>"


class DomainReputation(Base):
    """
    Domain reputation database for allowlist/denylist.
    
    Enables dynamic domain management without code deployment:
    - Mark official company domains (is_official=True)
    - Block known phishing domains (is_denied=True)
    - Add investigative notes for security analysis
    
    Security Note:
    This table is consulted during every QR analysis to make real-time
    reputation decisions. Ensure proper access controls on domain management endpoints.
    """
    __tablename__ = "domain_reputation"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    host = Column(String(255), unique=True, nullable=False, index=True)
    is_official = Column(Boolean, default=False, nullable=False)
    is_denied = Column(Boolean, default=False, nullable=False)
    note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    def __repr__(self) -> str:
        status = "OFFICIAL" if self.is_official else ("DENIED" if self.is_denied else "NEUTRAL")
        return f"<DomainReputation(host={self.host}, status={status})>"
