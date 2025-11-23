"""
Pydantic schemas for URL and QR code analysis API.
These schemas define the request/response structure for the frontend.
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, HttpUrl, Field
from datetime import datetime


# ============================================================================
# URL ANALYSIS SCHEMAS
# ============================================================================

class UrlAnalysisRequest(BaseModel):
    """Request schema for URL analysis."""
    url: str = Field(..., description="URL to analyze", example="https://www.google.com")
    client_app: Optional[str] = Field(None, description="Client application identifier")


class FormOverview(BaseModel):
    """Information about a form found on the page."""
    action: str = Field(..., description="Form action URL")
    method: str = Field(..., description="HTTP method (GET/POST)")
    is_external: bool = Field(..., description="Whether form submits to external domain")


class ContentInspection(BaseModel):
    """Detailed content inspection results from fetching and parsing the URL."""
    http_status: Optional[int] = Field(None, description="HTTP status code")
    content_type: Optional[str] = Field(None, description="Content-Type header")
    title: Optional[str] = Field(None, description="Page title from <title> tag")
    meta_description: Optional[str] = Field(None, description="Meta description")
    canonical_url: Optional[str] = Field(None, description="Canonical URL from <link> tag")
    
    script_count: int = Field(0, description="Number of <script> tags")
    form_count: int = Field(0, description="Number of <form> tags")
    iframe_count: int = Field(0, description="Number of <iframe> tags")
    
    form_overview: List[FormOverview] = Field(default_factory=list, description="Form details")
    external_domains: List[str] = Field(default_factory=list, description="External domains referenced")


class TechnicalDetails(BaseModel):
    """Technical details about the HTTP request/response."""
    raw_headers: Dict[str, str] = Field(default_factory=dict, description="Response headers")
    final_url_after_redirects: Optional[str] = Field(None, description="Final URL after following redirects")
    redirect_chain: List[str] = Field(default_factory=list, description="Redirect chain")
    fetch_time_ms: Optional[int] = Field(None, description="Time taken to fetch in milliseconds")
    tls_version: Optional[str] = Field(None, description="TLS version if HTTPS")


class AnalysisSummary(BaseModel):
    """High-level summary of the analysis for quick decision making."""
    short_verdict: str = Field(..., description="Brief verdict", example="Safe to proceed")
    recommended_action: str = Field(
        ..., 
        description="Recommended action: allow, warn, or block",
        pattern="^(allow|warn|block)$"
    )
    user_message: Optional[str] = Field(None, description="User-friendly message")


class UrlAnalysisResponse(BaseModel):
    """
    Complete URL analysis response.
    Designed to power a frontend with multiple tabs:
    - Summary Tab: summary, category, risk_score, risk_level, reasons
    - Content Tab: content_inspection
    - Technical Tab: technical_details
    - Log Tab: log_id, created_at
    """
    # Basic Info
    url: str = Field(..., description="Original URL submitted")
    normalized_url: str = Field(..., description="Normalized/cleaned URL")
    domain: str = Field(..., description="Extracted domain")
    
    # Risk Assessment
    category: str = Field(
        ..., 
        description="Domain category: official, trusted_third_party, or unknown_or_untrusted"
    )
    risk_score: int = Field(..., ge=0, le=100, description="Risk score from 0-100")
    risk_level: str = Field(..., description="Risk level: low, medium, or high")
    reasons: List[str] = Field(default_factory=list, description="Reasons for risk assessment")
    
    # Summary
    summary: AnalysisSummary = Field(..., description="Analysis summary")
    
    # Detailed Inspection
    content_inspection: ContentInspection = Field(..., description="Content inspection results")
    technical_details: TechnicalDetails = Field(..., description="Technical HTTP details")
    
    # Metadata
    log_id: str = Field(..., description="Database log ID for this scan")
    created_at: datetime = Field(..., description="Timestamp of analysis")
    
    class Config:
        json_schema_extra = {
            "example": {
                "url": "https://www.google.com",
                "normalized_url": "https://www.google.com/",
                "domain": "www.google.com",
                "category": "trusted_third_party",
                "risk_score": 5,
                "risk_level": "low",
                "reasons": ["Domain is in trusted third-party list (Google)"],
                "summary": {
                    "short_verdict": "Safe - Known search engine",
                    "recommended_action": "allow",
                    "user_message": "This is a well-known, legitimate website."
                },
                "content_inspection": {
                    "http_status": 200,
                    "content_type": "text/html",
                    "title": "Google",
                    "script_count": 5,
                    "form_count": 1,
                    "external_domains": ["www.googletagmanager.com"]
                },
                "technical_details": {
                    "final_url_after_redirects": "https://www.google.com/"
                },
                "log_id": "123e4567-e89b-12d3-a456-426614174000",
                "created_at": "2025-11-23T19:00:00Z"
            }
        }


# ============================================================================
# QR IMAGE ANALYSIS SCHEMAS
# ============================================================================

class QrImageAnalysisResponse(BaseModel):
    """Response schema for QR image analysis."""
    # QR Decode Results
    decoded_text: str = Field(..., description="Decoded text from QR code")
    looks_like_url: bool = Field(..., description="Whether decoded text appears to be a URL")
    
    # URL Analysis (if applicable)
    url_analysis: Optional[UrlAnalysisResponse] = Field(
        None, 
        description="Full URL analysis if decoded text is a URL"
    )
    
    # QR Metadata
    image_size_bytes: Optional[int] = Field(None, description="Image file size")
    image_format: Optional[str] = Field(None, description="Image format (PNG, JPEG, etc.)")
    image_dimensions: Optional[str] = Field(None, description="Image dimensions (width x height)")
    
    # Database Log
    qr_log_id: str = Field(..., description="Database log ID for this QR scan")
    created_at: datetime = Field(..., description="Timestamp of analysis")
    
    class Config:
        json_schema_extra = {
            "example": {
                "decoded_text": "https://example.com/charge/station123",
                "looks_like_url": True,
                "url_analysis": {
                    "url": "https://example.com/charge/station123",
                    "category": "unknown_or_untrusted",
                    "risk_score": 45,
                    "risk_level": "medium"
                },
                "qr_log_id": "123e4567-e89b-12d3-a456-426614174001"
            }
        }


# ============================================================================
# ERROR SCHEMAS
# ============================================================================

class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
