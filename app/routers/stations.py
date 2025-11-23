"""
Stations Management API Router.

Provides endpoints for managing charging stations and viewing their scan history.
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models_legacy import QRScan, Station
from app.schemas_legacy import PaginatedQRScans, QRScanRead

router = APIRouter(prefix="/api/stations", tags=["Stations"])


@router.get(
    "/{station_code}/scans",
    response_model=PaginatedQRScans,
    summary="Get Station Scan History",
    description="""
    Retrieve QR scan history for a specific charging station.
    
    This endpoint is useful for:
    - Security monitoring and audit
    - Identifying stations targeted by attackers
    - Analyzing attack patterns over time
    - Compliance and incident response
    
    Results are paginated and sorted by most recent first.
    """
)
async def get_station_scans(
    station_code: str,
    limit: int = Query(20, ge=1, le=100, description="Number of results to return"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
    db: AsyncSession = Depends(get_db)
) -> PaginatedQRScans:
    """
    Get scan history for a charging station.
    
    Args:
        station_code: Station identifier (e.g., "CP-001")
        limit: Maximum number of results to return
        offset: Number of results to skip (for pagination)
        db: Database session
        
    Returns:
        Paginated list of QR scans for the station
        
    Raises:
        HTTPException: If station not found
    """
    # Find station by code
    result = await db.execute(
        select(Station).where(Station.station_code == station_code)
    )
    station = result.scalar_one_or_none()
    
    if not station:
        raise HTTPException(
            status_code=404,
            detail=f"Station '{station_code}' not found"
        )
    
    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(QRScan).where(QRScan.station_id == station.id)
    )
    total = count_result.scalar() or 0
    
    # Get paginated scans, ordered by most recent first
    scans_result = await db.execute(
        select(QRScan)
        .where(QRScan.station_id == station.id)
        .order_by(QRScan.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    scans = scans_result.scalars().all()
    
    # Convert to response models
    scan_reads = [
        QRScanRead.model_validate(scan)
        for scan in scans
    ]
    
    return PaginatedQRScans(
        total=total,
        limit=limit,
        offset=offset,
        items=scan_reads
    )
