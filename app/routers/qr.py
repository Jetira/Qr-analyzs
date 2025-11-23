"""
QR Code Analysis API Router.

Provides endpoints for analyzing QR codes and determining security risks.
"""

import uuid
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.logging_utils import log_error, log_qr_scan_attempt
from app.models_legacy import QRScan
from app.schemas_legacy import QRAnalyzeRequest, QRAnalyzeResponse
from app.services.qr_analyzer import analyze_url
from app.services.notification import notify_security_event

from app.core.config import settings

router = APIRouter(prefix="/api", tags=["QR Analysis"])


@router.post(
    "/analyze-qr",
    response_model=QRAnalyzeResponse,
    summary="Analyze QR Code for Security Risks",
    description="""
    Analyze a scanned QR code and determine its security risk level.
    
    This endpoint performs comprehensive security analysis including:
    - HTTPS enforcement check
    - Domain verification against official allowlist
    - Typosquatting detection
    - Malicious file extension detection
    - Redirect vulnerability assessment
    - ML-based Phishing Detection
    - Dynamic QR Token Verification
    
    Returns a verdict (safe/suspicious/malicious), risk score, and detailed reasons.
    All analysis results are logged for audit and incident response purposes.
    """
)
async def analyze_qr(
    request: QRAnalyzeRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
) -> QRAnalyzeResponse:
    """
    Analyze a QR code for security risks.
    """
    try:
        qr_data = request.qr_data.strip()
        
        # Parse station_id if provided
        station_id_uuid: Optional[uuid.UUID] = None
        if request.station_id:
            try:
                station_id_uuid = uuid.UUID(request.station_id)
            except ValueError:
                # Invalid UUID format - log but continue analysis
                pass
        
        # ==========================================
        # STEP 1: Validate QR Content Format
        # ==========================================
        # Check if QR data looks like a URL
        try:
            parsed = urlparse(qr_data)
            has_scheme = bool(parsed.scheme)
            has_netloc = bool(parsed.netloc)
            is_url = has_scheme and has_netloc
        except Exception:
            is_url = False
        
        # If not a URL, mark as suspicious
        if not is_url:
            response = QRAnalyzeResponse(
                verdict="suspicious",
                score=50,
                reasons=["Beklenmeyen QR içeriği (URL değil veya geçersiz format)"],
                normalized_url=None,
                host=None
            )
        else:
            # ==========================================
            # STEP 2: Analyze URL Security
            # ==========================================
            response = await analyze_url(qr_data, settings, db)
        
        # ==========================================
        # STEP 3: Store Audit Log
        # ==========================================
        # Create database record
        qr_scan = QRScan(
            id=uuid.uuid4(),
            station_id=station_id_uuid,
            raw_qr_data=qr_data,
            parsed_url=response.normalized_url,
            host=response.host,
            verdict=response.verdict,
            score=response.score,
            reasons=response.reasons,  # Stored as JSONB
            app_version=request.app_version,
            platform=request.platform
        )
        
        db.add(qr_scan)
        await db.commit()
        
        # ==========================================
        # STEP 4: Log Event & Notify
        # ==========================================
        log_qr_scan_attempt(
            station_id=request.station_id,
            raw_qr_data=qr_data,
            verdict=response.verdict,
            score=response.score,
            host=response.host,
            reasons=response.reasons,
            app_version=request.app_version,
            platform=request.platform
        )
        
        # Send Notifications (Background Task)
        if response.verdict in ["malicious", "suspicious"]:
            background_tasks.add_task(
                notify_security_event,
                station_id=str(request.station_id) if request.station_id else "unknown",
                verdict=response.verdict,
                score=response.score,
                url=response.normalized_url,
                reasons=response.reasons
            )
        
        return response
        
    except Exception as e:
        # Log error with context
        log_error(
            "QR analysis failed",
            e,
            context={
                "station_id": request.station_id,
                "platform": request.platform
            }
        )
        
        # Return generic error response
        raise HTTPException(
            status_code=500,
            detail="QR analizi sırasında bir hata oluştu"
        )
