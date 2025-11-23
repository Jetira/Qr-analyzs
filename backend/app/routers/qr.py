"""
QR Code Analysis API Router.

Provides endpoints for:
- QR code security analysis
- Station scan history
- Domain reputation management
"""

import uuid
import logging
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.config import settings
from app.models import Station, QRScan, DomainReputation
from app.schemas import (
    QRAnalyzeRequest,
    QRAnalyzeResponse,
    QRScanResponse,
    DomainReputationCreate,
    DomainReputationResponse,
)
from app.services.qr_analyzer import analyze_url
from app.logging_utils import SecurityEventLogger

logger = logging.getLogger(__name__)
security_logger = SecurityEventLogger()

router = APIRouter()


# ============================================================================
# POST /analyze-qr - Primary QR Analysis Endpoint
# ============================================================================

@router.post("/analyze-qr", response_model=QRAnalyzeResponse)
async def analyze_qr(
    request: QRAnalyzeRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Analyze a QR code for security risks.
    
    This is the primary endpoint called by the mobile app whenever a user
    scans a QR code. The analysis happens BEFORE the URL is opened.
    
    Workflow:
    1. Validate QR data format
    2. Parse as URL (if possible)
    3. Run security analysis (5 rules)
    4. Log to database for audit trail
    5. Return verdict to mobile app
    
    Mobile app decision tree based on verdict:
    - safe: Open URL directly
    - suspicious: Show warning dialog, let user decide
    - malicious: Block and show error message
    
    Args:
        request: QRAnalyzeRequest with qr_data, station_id, etc.
        db: Database session (injected)
    
    Returns:
        QRAnalyzeResponse with verdict, score, and reasons
    
    Raises:
        HTTPException: If request validation fails
    """
    logger.info(f"QR analysis request from station: {request.station_id}")
    
    # ========================================================================
    # Step 1: Attempt to parse QR data as URL
    # ========================================================================
    try:
        parsed = urlparse(request.qr_data)
        
        # Check if it looks like a valid URL
        # A valid URL should have at least a scheme or netloc
        if not parsed.scheme and not parsed.netloc:
            # QR data doesn't look like a URL - suspicious
            logger.warning(f"Non-URL QR data received: {request.qr_data[:50]}")
            
            response = QRAnalyzeResponse(
                verdict="suspicious",
                score=50,
                reasons=["Beklenmeyen QR içeriği (URL formatında değil)"],
                normalized_url=None,
                host=None
            )
            
            # Still log it for audit purposes
            await _create_scan_record(
                db=db,
                request=request,
                response=response,
                parsed_url=None,
                host=None
            )
            
            return response
        
        # If scheme is missing but netloc exists, assume https
        if not parsed.scheme and parsed.netloc:
            normalized_url = f"https://{request.qr_data}"
            parsed = urlparse(normalized_url)
        else:
            normalized_url = request.qr_data
    
    except Exception as e:
        logger.error(f"Failed to parse QR data: {e}")
        
        # Return a suspicious verdict for unparseable data
        response = QRAnalyzeResponse(
            verdict="suspicious",
            score=60,
            reasons=["QR verisi işlenemedi (geçersiz format)"],
            normalized_url=None,
            host=None
        )
        
        await _create_scan_record(
            db=db,
            request=request,
            response=response,
            parsed_url=None,
            host=None
        )
        
        return response
    
    # ========================================================================
    # Step 2: Run security analysis
    # ========================================================================
    response = await analyze_url(
        url=normalized_url,
        settings=settings,
        db=db
    )
    
    # ========================================================================
    # Step 3: Create audit log record
    # ========================================================================
    host = parsed.netloc if parsed.netloc else None
    
    await _create_scan_record(
        db=db,
        request=request,
        response=response,
        parsed_url=normalized_url,
        host=host
    )
    
    # ========================================================================
    # Step 4: Log security event
    # ========================================================================
    security_logger.log_qr_scan(
        station_id=request.station_id,
        verdict=response.verdict,
        score=response.score,
        url=normalized_url,
        host=host,
        platform=request.platform,
        app_version=request.app_version
    )
    
    return response


async def _create_scan_record(
    db: AsyncSession,
    request: QRAnalyzeRequest,
    response: QRAnalyzeResponse,
    parsed_url: Optional[str],
    host: Optional[str]
) -> None:
    """
    Create a QRScan record in the database for audit trail.
    
    Args:
        db: Database session
        request: Original request
        response: Analysis response
        parsed_url: Normalized URL
        host: Extracted hostname
    """
    # Find station by station_code if provided
    station_id = None
    if request.station_id:
        result = await db.execute(
            select(Station).where(Station.station_code == request.station_id)
        )
        station = result.scalar_one_or_none()
        if station:
            station_id = station.id
        else:
            logger.warning(f"Station not found: {request.station_id}")
    
    # Create scan record
    scan = QRScan(
        id=uuid.uuid4(),
        station_id=station_id,
        raw_qr_data=request.qr_data,
        parsed_url=parsed_url,
        host=host,
        verdict=response.verdict,
        score=response.score,
        reasons=response.reasons,  # SQLAlchemy will serialize to JSON
        app_version=request.app_version,
        platform=request.platform,
    )
    
    db.add(scan)
    await db.commit()
    logger.info(f"QR scan logged: {scan.id}")


# ============================================================================
# GET /stations/{station_code}/scans - Scan History
# ============================================================================

@router.get("/stations/{station_code}/scans", response_model=List[QRScanResponse])
async def get_station_scans(
    station_code: str,
    limit: int = Query(50, ge=1, le=200, description="Maximum number of records to return"),
    offset: int = Query(0, ge=0, description="Number of records to skip"),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieve QR scan history for a specific charging station.
    
    Use cases:
    - Security team investigating suspicious activity
    - Station manager reviewing scan patterns
    - Automated alerts for repeated malicious scans
    
    Returns scans in reverse chronological order (newest first).
    
    Args:
        station_code: Station identifier (e.g., "CP-001")
        limit: Max results (default 50, max 200)
        offset: Pagination offset (default 0)
        db: Database session
    
    Returns:
        List of QRScanResponse objects
    
    Raises:
        HTTPException 404: If station not found
    """
    # Find station
    result = await db.execute(
        select(Station).where(Station.station_code == station_code)
    )
    station = result.scalar_one_or_none()
    
    if not station:
        raise HTTPException(status_code=404, detail=f"Station not found: {station_code}")
    
    # Query scans with pagination
    result = await db.execute(
        select(QRScan)
        .where(QRScan.station_id == station.id)
        .order_by(QRScan.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    scans = result.scalars().all()
    
    return scans


# ============================================================================
# POST /domains - Domain Reputation Management
# ============================================================================

@router.post("/domains", response_model=DomainReputationResponse)
async def create_or_update_domain(
    domain_data: DomainReputationCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Add or update domain reputation.
    
    Use cases:
    - Add official company domains to allowlist
    - Block newly discovered phishing domains
    - Update investigation notes
    
    Security Note:
    In production, this endpoint should be protected with authentication
    and authorization. Only security team members should be able to
    modify domain reputation.
    
    Args:
        domain_data: Domain information
        db: Database session
    
    Returns:
        DomainReputationResponse with created/updated record
    """
    host_lower = domain_data.host.lower().strip()
    
    # Check if domain already exists
    result = await db.execute(
        select(DomainReputation).where(DomainReputation.host == host_lower)
    )
    existing = result.scalar_one_or_none()
    
    if existing:
        # Update existing record
        existing.is_official = domain_data.is_official
        existing.is_denied = domain_data.is_denied
        existing.note = domain_data.note
        
        await db.commit()
        await db.refresh(existing)
        
        logger.info(f"Updated domain reputation: {host_lower}")
        security_logger.log_domain_reputation_change(
            host=host_lower,
            is_official=domain_data.is_official,
            is_denied=domain_data.is_denied,
            note=domain_data.note
        )
        
        return existing
    else:
        # Create new record
        new_domain = DomainReputation(
            host=host_lower,
            is_official=domain_data.is_official,
            is_denied=domain_data.is_denied,
            note=domain_data.note,
        )
        
        db.add(new_domain)
        await db.commit()
        await db.refresh(new_domain)
        
        logger.info(f"Created domain reputation: {host_lower}")
        security_logger.log_domain_reputation_change(
            host=host_lower,
            is_official=domain_data.is_official,
            is_denied=domain_data.is_denied,
            note=domain_data.note
        )
        
        return new_domain


# ============================================================================
# GET /domains - List Domain Reputations
# ============================================================================

@router.get("/domains", response_model=List[DomainReputationResponse])
async def list_domains(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """
    List all domain reputation entries.
    
    Args:
        limit: Max results
        offset: Pagination offset
        db: Database session
    
    Returns:
        List of DomainReputationResponse objects
    """
    result = await db.execute(
        select(DomainReputation)
        .order_by(DomainReputation.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    domains = result.scalars().all()
    
    return domains
