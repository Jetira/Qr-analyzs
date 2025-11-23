"""
API Router for Station Anomaly Detection.

Provides endpoints to analyze station behavior and detect anomalies
using unsupervised machine learning.
"""

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.logging_utils import log_error
from app.models_legacy import Station
from app.services.anomaly_detector import (
    anomaly_score,
    build_station_feature_vector,
    classify_anomaly,
)

router = APIRouter(
    prefix="/api/anomaly",
    tags=["Anomaly Detection"],
    responses={404: {"description": "Not found"}},
)


@router.get("/station/{station_code}")
async def detect_station_anomaly(
    station_code: str,
    window_minutes: int = Query(60, ge=10, le=1440, description="Analysis window in minutes"),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """
    Analyze a station for behavioral anomalies.
    
    Calculates an anomaly score based on recent scan activity (volume,
    risk scores, domain types) using an unsupervised ML model.
    
    Args:
        station_code: The unique code of the station
        window_minutes: How far back to look (default 60 mins)
        
    Returns:
        JSON object with anomaly score, label, and feature details
    """
    try:
        # 1. Find station
        result = await db.execute(select(Station).where(Station.station_code == station_code))
        station = result.scalar_one_or_none()
        
        if not station:
            raise HTTPException(status_code=404, detail="Station not found")
            
        # 2. Build feature vector
        features, feature_dict = await build_station_feature_vector(
            db, str(station.id), window_minutes
        )
        
        # 3. Compute anomaly score
        score = anomaly_score(features)
        
        # 4. Classify
        label = classify_anomaly(score)
        
        return {
            "station_code": station_code,
            "window_minutes": window_minutes,
            "anomaly_score": round(score, 2),
            "anomaly_label": label,
            "features": feature_dict
        }
        
    except HTTPException:
        raise
    except Exception as e:
        log_error(f"Anomaly detection failed for {station_code}", e)
        raise HTTPException(status_code=500, detail="Internal server error during anomaly detection")
