"""
Pydantic models for request/response validation.

Defines:
- Request/response schemas for QR analysis
- Schemas for Station and QRScan management
- Domain reputation management schemas
"""

from datetime import datetime
from typing import List, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, Field


# ==========================
# QR Analysis Schemas
# ==========================

class QRAnalyzeRequest(BaseModel):
    """
    Request model for QR code analysis.
    
    Sent by mobile app when user scans a QR code.
    """
    qr_data: str = Field(
        ...,
        description="Raw QR code content as scanned",
        min_length=1
    )
    
    station_id: Optional[str] = Field(
        None,
        description="UUID of the charging station (if known)"
    )
    
    app_version: Optional[str] = Field(
        None,
        description="Mobile app version (e.g., '1.2.3')",
        max_length=50
    )
    
    platform: Optional[str] = Field(
        None,
        description="Platform identifier (e.g., 'android', 'ios')",
        max_length=20
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "qr_data": "https://charge.official-domain.com/start?station=CP-001",
                "station_id": "550e8400-e29b-41d4-a716-446655440000",
                "app_version": "1.0.0",
                "platform": "android"
            }
        }


class QRAnalyzeResponse(BaseModel):
    """
    Response model for QR code analysis.
    
    Contains risk assessment and verdict for the scanned QR code.
    """
    verdict: Literal["safe", "suspicious", "malicious"] = Field(
        ...,
        description="Overall risk verdict"
    )
    
    score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Risk score from 0 (safe) to 100 (very dangerous)"
    )
    
    reasons: List[str] = Field(
        ...,
        description="List of security issues detected"
    )
    
    normalized_url: Optional[str] = Field(
        None,
        description="Normalized URL (if QR contains a URL)"
    )
    
    host: Optional[str] = Field(
        None,
        description="Hostname extracted from URL"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "verdict": "malicious",
                "score": 95,
                "reasons": [
                    "HTTPS değil",
                    "Resmi domain değil",
                    "APK indirme tespit edildi"
                ],
                "normalized_url": "http://fake-site.com/malicious.apk",
                "host": "fake-site.com"
            }
        }


# ==========================
# Station Schemas
# ==========================

class StationBase(BaseModel):
    """Base schema for Station."""
    station_code: str = Field(..., max_length=50)
    location: Optional[str] = Field(None, max_length=255)
    is_active: bool = Field(True)


class StationCreate(StationBase):
    """Schema for creating a new station."""
    pass


class StationRead(StationBase):
    """Schema for reading station data."""
    id: UUID
    
    class Config:
        from_attributes = True


# ==========================
# QR Scan Schemas
# ==========================

class QRScanRead(BaseModel):
    """
    Schema for reading QR scan records.
    
    Used for listing scan history and audit logs.
    """
    id: UUID
    station_id: Optional[UUID]
    raw_qr_data: str
    parsed_url: Optional[str]
    host: Optional[str]
    verdict: str
    score: int
    reasons: List[str]  # JSONB is deserialized to list
    app_version: Optional[str]
    platform: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "station_id": "660e8400-e29b-41d4-a716-446655440000",
                "raw_qr_data": "http://malicious.com/fake.apk",
                "parsed_url": "http://malicious.com/fake.apk",
                "host": "malicious.com",
                "verdict": "malicious",
                "score": 95,
                "reasons": ["HTTPS değil", "APK indirme tespit edildi"],
                "app_version": "1.0.0",
                "platform": "android",
                "created_at": "2023-11-22T10:30:00Z"
            }
        }


# ==========================
# Domain Reputation Schemas
# ==========================

class DomainReputationBase(BaseModel):
    """Base schema for Domain Reputation."""
    host: str = Field(..., max_length=255)
    is_official: bool = Field(False)
    is_denied: bool = Field(False)
    note: Optional[str] = None


class DomainReputationCreate(DomainReputationBase):
    """Schema for creating/updating domain reputation."""
    pass


class DomainReputationRead(DomainReputationBase):
    """Schema for reading domain reputation."""
    id: int
    
    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": 1,
                "host": "official-domain.com",
                "is_official": True,
                "is_denied": False,
                "note": "Primary official domain for EV charging service"
            }
        }


# ==========================
# Paginated Response Schemas
# ==========================

class PaginatedQRScans(BaseModel):
    """Paginated response for QR scan listings."""
    total: int
    limit: int
    offset: int
    items: List[QRScanRead]
