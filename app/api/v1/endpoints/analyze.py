"""
Analysis API Endpoints for URL and QR Code Security Scanning.

Provides:
- POST /api/v1/analyze/url - Analyze a URL for security risks
- POST /api/v1/analyze/qr-image - Upload and analyze a QR code image
"""
import uuid
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.scan import UrlScan, QrScan
from app.schemas.analysis import (
    UrlAnalysisRequest,
    UrlAnalysisResponse,
    QrImageAnalysisResponse,
    AnalysisSummary,
    ContentInspection,
    TechnicalDetails,
    FormOverview,
    ErrorResponse
)
from app.services.risk_scoring import risk_scorer
from app.services.url_inspector import url_inspector
from app.services.qr_decoder import qr_decoder

router = APIRouter()


def normalize_url(url: str) -> str:
    """Normalize URL for consistent processing."""
    url = url.strip()
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Ensure trailing slash for domain-only URLs
    parsed = urlparse(url)
    if parsed.path == '' and parsed.query == '':
        url += '/'
    
    return url


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except:
        return ""


def get_client_ip(request: Request) -> Optional[str]:
    """Extract client IP from request."""
    if "x-forwarded-for" in request.headers:
        return request.headers["x-forwarded-for"].split(",")[0].strip()
    return request.client.host if request.client else None


@router.post(
    "/url",
    response_model=UrlAnalysisResponse,
    responses={
        200: {"description": "URL analysis completed successfully"},
        400: {"model": ErrorResponse, "description": "Invalid URL"},
        500: {"model": ErrorResponse, "description": "Internal server error"}
    },
    summary="Analyze URL for Security Risks",
    description="""
    Analyze a URL for security threats using multi-factor risk assessment.
    
    This endpoint:
    1. Classifies the domain (official / trusted third-party / unknown)
    2. Calculates risk score based on multiple factors
    3. Fetches and inspects the URL content (HTML, forms, scripts)
    4. Logs the analysis to the database
    5. Returns comprehensive results for frontend tabs
    
    **Risk Classification:**
    - Official domains: Minimal risk
    - Trusted third-parties (Google, Apple, etc.): Low baseline risk
    - Unknown domains: Risk determined by URL characteristics
    """
)
async def analyze_url(
    request_data: UrlAnalysisRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """Analyze a URL for security threats and return detailed assessment."""
    
    try:
        # Normalize URL
        original_url = request_data.url
        normalized_url = normalize_url(original_url)
        domain = extract_domain(normalized_url)
        
        if not domain:
            raise HTTPException(status_code=400, detail="Invalid URL: could not extract domain")
        
        # Step 1: Risk Scoring
        category, risk_score, risk_level, reasons = risk_scorer.analyze_url(normalized_url)
        
        # Step 2: Generate recommended action and verdict
        recommended_action = risk_scorer.get_recommended_action(risk_level, category)
        verdict = risk_scorer.get_user_friendly_verdict(category, risk_level, domain)
        
        # Step 3: Fetch and inspect URL content (async)
        inspection_result = await url_inspector.inspect_url(normalized_url)
        
        # Step 4: Build response structure
        
        # Content Inspection
        content_inspection = ContentInspection(
            http_status=inspection_result.get("http_status"),
            content_type=inspection_result.get("content_type"),
            title=inspection_result.get("title"),
            meta_description=inspection_result.get("meta_description"),
            canonical_url=inspection_result.get("canonical_url"),
            script_count=inspection_result.get("script_count", 0),
            form_count=inspection_result.get("form_count", 0),
            iframe_count=inspection_result.get("iframe_count", 0),
            form_overview=[
                FormOverview(**form) for form in inspection_result.get("form_details", [])
            ],
            external_domains=inspection_result.get("external_domains", [])
        )
        
        # Technical Details
        technical_details = TechnicalDetails(
            raw_headers=inspection_result.get("headers", {}),
            final_url_after_redirects=inspection_result.get("final_url"),
            redirect_chain=inspection_result.get("redirect_chain", []),
            fetch_time_ms=inspection_result.get("fetch_time_ms")
        )
        
        # Summary
        summary = AnalysisSummary(
            short_verdict=verdict,
            recommended_action=recommended_action,
            user_message=verdict
        )
        
        # Step 5: Save to database
        scan_id = str(uuid.uuid4())
        url_scan = UrlScan(
            id=scan_id,
            original_url=original_url,
            normalized_url=normalized_url,
            domain=domain,
            category=category,
            risk_score=risk_score,
            risk_level=risk_level,
            reasons=reasons,
            summary_verdict=verdict,
            recommended_action=recommended_action,
            http_status=inspection_result.get("http_status"),
            content_type=inspection_result.get("content_type"),
            page_title=inspection_result.get("title"),
            meta_description=inspection_result.get("meta_description"),
            canonical_url=inspection_result.get("canonical_url"),
            script_count=inspection_result.get("script_count", 0),
            form_count=inspection_result.get("form_count", 0),
            iframe_count=inspection_result.get("iframe_count", 0),
            external_domains=inspection_result.get("external_domains"),
            form_details=inspection_result.get("form_details"),
            final_url_after_redirects=inspection_result.get("final_url"),
            redirect_chain=inspection_result.get("redirect_chain"),
            response_headers=inspection_result.get("headers"),
            client_app=request_data.client_app,
            client_ip=get_client_ip(request),
            created_at=datetime.utcnow()
        )
        
        db.add(url_scan)
        await db.commit()
        
        # Step 6: Build and return response
        response = UrlAnalysisResponse(
            url=original_url,
            normalized_url=normalized_url,
            domain=domain,
            category=category,
            risk_score=risk_score,
            risk_level=risk_level,
            reasons=reasons,
            summary=summary,
            content_inspection=content_inspection,
            technical_details=technical_details,
            log_id=scan_id,
            created_at=url_scan.created_at
        )
        
        return response
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post(
    "/qr-image",
    response_model=QrImageAnalysisResponse,
    responses={
        200: {"description": "QR code decoded and analyzed successfully"},
        400: {"model": ErrorResponse, "description": "Invalid image or QR code not found"},
        500: {"model": ErrorResponse, "description": "Internal server error"}
    },
    summary="Upload and Analyze QR Code Image",
    description="""
    Upload a QR code image for decoding and security analysis.
    
    This endpoint:
    1. Decodes the QR code from the uploaded image
    2. If the QR contains a URL, performs full URL analysis
    3. Logs both the QR scan and URL analysis to the database
    4. Returns decoded text plus full URL analysis results
    
    **Supported formats:** PNG, JPEG, GIF, BMP
    **Max file size:** 10MB
    """
)
async def analyze_qr_image(
    file: UploadFile = File(..., description="QR code image file"),
    request: Request = None,
    db: AsyncSession = Depends(get_db)
):
    """Upload and analyze a QR code image."""
    
    try:
        # Read file content
        file_content = await file.read()
        
        # Decode QR code
        decoded_text, qr_metadata = await qr_decoder.decode_qr_image(file_content, file.filename)
        
        if not decoded_text:
            error_msg = qr_metadata.get("error", "Could not decode QR code")
            raise HTTPException(status_code=400, detail=error_msg)
        
        # Check if decoded text is a URL
        is_url = qr_decoder.looks_like_url(decoded_text)
        
        # Initialize response data
        url_analysis = None
        linked_url_scan_id = None
        
        # If it's a URL, run full URL analysis
        if is_url:
            # Ensure it's a well-formed URL
            url_to_analyze = decoded_text
            if not url_to_analyze.startswith(('http://', 'https://')):
                url_to_analyze = 'https://' + url_to_analyze
            
            # Create URL analysis request
            url_request = UrlAnalysisRequest(url=url_to_analyze)
            
            # Perform URL analysis
            url_analysis = await analyze_url(url_request, request, db)
            linked_url_scan_id = url_analysis.log_id
        
        # Save QR scan to database
        qr_scan_id = str(uuid.uuid4())
        qr_scan = QrScan(
            id=qr_scan_id,
            decoded_text=decoded_text,
            is_url=is_url,
            linked_url_scan_id=linked_url_scan_id,
            image_size_bytes=qr_metadata.get("size_bytes"),
            image_format=qr_metadata.get("format"),
            image_dimensions=qr_metadata.get("dimensions"),
            client_ip=get_client_ip(request) if request else None,
            created_at=datetime.utcnow()
        )
        
        db.add(qr_scan)
        await db.commit()
        
        # Build response
        response = QrImageAnalysisResponse(
            decoded_text=decoded_text,
            looks_like_url=is_url,
            url_analysis=url_analysis,
            image_size_bytes=qr_metadata.get("size_bytes"),
            image_format=qr_metadata.get("format"),
            image_dimensions=qr_metadata.get("dimensions"),
            qr_log_id=qr_scan_id,
            created_at=qr_scan.created_at
        )
        
        return response
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
