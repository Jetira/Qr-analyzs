"""
Database models for URL and QR scan logging.
These models support comprehensive logging for security analysis and audit trails.
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Boolean, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.db.base import Base


class UrlScan(Base):
    """
    Logs every URL analysis performed by the system.
    Stores risk assessment, content inspection results, and metadata.
    """
    __tablename__ = "url_scans"
    
    # Primary key - using String for universal compatibility
    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True
    )
    
    # URL Information
    original_url = Column(Text, nullable=False, index=True)
    normalized_url = Column(Text, nullable=False)
    domain = Column(String(255), nullable=False, index=True)
    
    # Risk Assessment
    category = Column(
        String(50), 
        nullable=False, 
        index=True,
        comment="official, trusted_third_party, or unknown_or_untrusted"
    )
    risk_score = Column(Integer, nullable=False, index=True, comment="0-100 risk score")
    risk_level = Column(
        String(20), 
        nullable=False, 
        index=True,
        comment="low, medium, or high"
    )
    reasons = Column(JSON, nullable=True, comment="List of reasons for risk assessment")
    
    # Summary
    summary_verdict = Column(Text, nullable=True, comment="Human-readable verdict")
    recommended_action = Column(
        String(20), 
        nullable=True,
        comment="allow, warn, or block"
    )
    
    # Content Inspection Results
    http_status = Column(Integer, nullable=True)
    content_type = Column(String(100), nullable=True)
    page_title = Column(Text, nullable=True)
    meta_description = Column(Text, nullable=True)
    canonical_url = Column(Text, nullable=True)
    
    script_count = Column(Integer, default=0)
    form_count = Column(Integer, default=0)
    iframe_count = Column(Integer, default=0)
    
    external_domains = Column(JSON, nullable=True, comment="List of external domains")
    form_details = Column(JSON, nullable=True, comment="Form analysis data")
    
    # Technical Details
    final_url_after_redirects = Column(Text, nullable=True)
    redirect_chain = Column(JSON, nullable=True)
    response_headers = Column(JSON, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    client_app = Column(String(100), nullable=True, comment="Client app name/version")
    client_ip = Column(String(45), nullable=True)
    
    # Relationships
    qr_scans = relationship("QrScan", back_populates="url_scan")
    
    def __repr__(self):
        return f"<UrlScan(id={self.id}, domain={self.domain}, risk={self.risk_level})>"


class QrScan(Base):
    """
    Logs every QR code scan/analysis performed by the system.
    Links to UrlScan if the QR contains a URL.
    """
    __tablename__ = "qr_scans"
    
    # Primary key - using String for universal compatibility
    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True
    )
    
    # QR Code Data
    decoded_text = Column(Text, nullable=False, comment="Raw decoded text from QR")
    is_url = Column(Boolean, default=False, nullable=False, index=True)
    
    # Link to URL analysis (if applicable)
    linked_url_scan_id = Column(
        String(36),
        ForeignKey("url_scans.id"),
        nullable=True,
        index=True
    )
    
    # Image metadata
    image_size_bytes = Column(Integer, nullable=True)
    image_format = Column(String(20), nullable=True)
    image_dimensions = Column(String(50), nullable=True, comment="width x height")
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    client_app = Column(String(100), nullable=True, comment="Client app name/version")
    client_ip = Column(String(45), nullable=True)
    
    # Relationships
    url_scan = relationship("UrlScan", back_populates="qr_scans")
    
    def __repr__(self):
        return f"<QrScan(id={self.id}, is_url={self.is_url})>"
