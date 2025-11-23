"""
Pydantic models for request/response validation.
Defines the API contract for QR Security Service.
"""

from typing import List, Optional
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


# ============================================================================
# QR Analysis Schemas
# ============================================================================

class QRAnalyzeRequest(BaseModel):
    """
    Request model for QR code analysis.
    
    The mobile app sends this when a user scans a QR code.
    Analysis happens BEFORE the URL is opened in the webview.
    """
    qr_data: str = Field(
        ..., 
        description="Raw QR code content (typically a URL)",
        min_length=1
    )
    station_id: Optional[str] = Field(
        None, 
        description="Station code where QR was scanned (e.g., 'CP-001')"
    )
    app_version: Optional[str] = Field(
        None, 
        description="Mobile app version (e.g., '1.2.3')"
    )
    platform: Optional[str] = Field(
        None, 
        description="Device platform: 'android' or 'ios'"
    )


class QRAnalyzeResponse(BaseModel):
    """
    Response model for QR code analysis.
    
    Mobile app uses this to decide whether to:
    - Open the URL (safe)
    - Show warning dialog (suspicious)
    - Block completely (malicious)
    """
    verdict: str = Field(
        ..., 
        description="Security verdict: 'safe', 'suspicious', or 'malicious'"
    )
    score: int = Field(
        ..., 
        description="Risk score from 0 (safe) to 100 (malicious)",
        ge=0,
        le=100
    )
    reasons: List[str] = Field(
        ..., 
        description="Human-readable list of security findings"
    )
    normalized_url: Optional[str] = Field(
        None, 
        description="Parsed and normalized URL (if valid)"
    )
    host: Optional[str] = Field(
        None, 
        description="Extracted hostname (if URL is valid)"
    )


# ============================================================================
# Station Schemas
# ============================================================================

class StationCreate(BaseModel):
    """Request model for creating a new charging station."""
    station_code: str = Field(..., min_length=1, max_length=50)
    location: Optional[str] = Field(None, max_length=255)
    is_active: bool = True


class StationResponse(BaseModel):
    """Response model for station data."""
    id: UUID
    station_code: str
    location: Optional[str]
    is_active: bool
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Domain Reputation Schemas
# ============================================================================

class DomainReputationCreate(BaseModel):
    """
    Request model for adding/updating domain reputation.
    
    Use cases:
    - Add official company domains to allowlist
    - Block newly discovered phishing domains
    - Add investigative notes for security team
    """
    host: str = Field(..., min_length=1, max_length=255, description="Domain name (e.g., 'example.com')")
    is_official: bool = Field(False, description="True if this is an official company domain")
    is_denied: bool = Field(False, description="True if this domain should be blocked")
    note: Optional[str] = Field(None, description="Investigation notes or context")


class DomainReputationResponse(BaseModel):
    """Response model for domain reputation data."""
    id: int
    host: str
    is_official: bool
    is_denied: bool
    note: Optional[str]
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# QR Scan History Schemas
# ============================================================================

class QRScanResponse(BaseModel):
    """
    Response model for historical QR scan records.
    
    Used by the audit endpoint to retrieve scan history for a station.
    """
    id: UUID
    station_id: Optional[UUID]
    raw_qr_data: str
    parsed_url: Optional[str]
    host: Optional[str]
    verdict: str
    score: int
    reasons: List[str]
    app_version: Optional[str]
    platform: Optional[str]
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Health Check Schema
# ============================================================================

class HealthResponse(BaseModel):
    """Response model for health check endpoint."""
    status: str = Field(..., description="Service status: 'ok' or 'error'")
    app: str = Field(..., description="Application name")
    version: str = Field(..., description="Application version")
