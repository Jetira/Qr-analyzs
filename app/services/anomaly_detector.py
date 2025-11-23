"""
Station-Level Behavioural Anomaly Detector (Unsupervised ML).

This module detects abnormal patterns in station activity, such as:
- Spikes in scan volume
- High ratio of non-official domains
- Unusual number of malicious scans

It uses an unsupervised approach (Isolation Forest) or statistical heuristics
to flag stations that deviate from normal behavior.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logging_utils import log_error
from app.models_legacy import QRScan, Station


async def build_station_feature_vector(
    db: AsyncSession,
    station_id: str,  # UUID as string
    window_minutes: int = 60
) -> Tuple[np.ndarray, Dict[str, float]]:
    """
    Build a feature vector for a station based on recent activity.
    
    Features:
    1. Scan count
    2. Official domain ratio
    3. Non-official domain ratio
    4. APK/EXE URL ratio
    5. Average risk score
    6. Malicious scan count
    
    Args:
        db: Database session
        station_id: Station UUID
        window_minutes: Time window to analyze (default: 60 min)
        
    Returns:
        Tuple of (feature_vector, feature_dict)
    """
    # Calculate time window
    start_time = datetime.utcnow() - timedelta(minutes=window_minutes)
    
    # Query scans for this station in the time window
    # Note: In a real production system, this aggregation should be done 
    # via optimized SQL queries or a time-series DB, not by fetching all rows.
    result = await db.execute(
        select(QRScan).where(
            QRScan.station_id == station_id,
            QRScan.created_at >= start_time
        )
    )
    scans = result.scalars().all()
    
    if not scans:
        # No data - return zero vector
        features = np.zeros((1, 6))
        feature_dict = {
            "scan_count": 0,
            "official_domain_ratio": 0.0,
            "non_official_domain_ratio": 0.0,
            "apk_url_ratio": 0.0,
            "average_risk_score": 0.0,
            "malicious_count": 0
        }
        return features, feature_dict
    
    # Calculate statistics
    total_scans = len(scans)
    malicious_count = sum(1 for s in scans if s.verdict == "malicious")
    avg_score = sum(s.score for s in scans) / total_scans
    
    # Heuristic for official domains (score < 40 usually means safe/official)
    official_count = sum(1 for s in scans if s.score < 40)
    non_official_count = total_scans - official_count
    
    # Check for APK/EXE in raw data (simple check)
    apk_count = sum(1 for s in scans if any(x in s.raw_qr_data.lower() for x in ['.apk', '.exe']))
    
    # Ratios
    official_ratio = official_count / total_scans
    non_official_ratio = non_official_count / total_scans
    apk_ratio = apk_count / total_scans
    
    # Create feature vector
    features = np.array([
        total_scans,
        official_ratio,
        non_official_ratio,
        apk_ratio,
        avg_score,
        malicious_count
    ]).reshape(1, -1)
    
    feature_dict = {
        "scan_count": total_scans,
        "official_domain_ratio": round(official_ratio, 2),
        "non_official_domain_ratio": round(non_official_ratio, 2),
        "apk_url_ratio": round(apk_ratio, 2),
        "average_risk_score": round(avg_score, 1),
        "malicious_count": malicious_count
    }
    
    return features, feature_dict


def anomaly_score(features: np.ndarray) -> float:
    """
    Compute anomaly score for the given feature vector.
    
    In a full implementation, this would use a pre-trained IsolationForest
    model loaded from disk. For this demonstration, we'll use a simplified
    heuristic or a small in-memory model fit on synthetic 'normal' data.
    
    Args:
        features: Feature vector from build_station_feature_vector
        
    Returns:
        Anomaly score (0.0 to 1.0, higher is more anomalous)
    """
    try:
        # SIMULATION: Fit a model on synthetic "normal" data on the fly
        # In production, load a pre-trained model!
        
        # Generate synthetic normal data (e.g., low scan counts, mostly official domains)
        rng = np.random.RandomState(42)
        X_train = 0.3 * rng.randn(100, 6)
        # Shift means to represent "normal" behavior:
        # [scan_count, off_ratio, non_off_ratio, apk_ratio, avg_score, mal_count]
        # Normal: ~10 scans, 0.9 official, 0.1 non-official, 0 APK, score 10, 0 malicious
        X_train[:, 0] += 10   # scans
        X_train[:, 1] += 0.9  # official ratio
        X_train[:, 2] += 0.1  # non-official
        X_train[:, 3] += 0.0  # apk
        X_train[:, 4] += 10   # score
        X_train[:, 5] += 0    # malicious
        
        # Fit Isolation Forest
        clf = IsolationForest(random_state=42, contamination=0.1)
        clf.fit(X_train)
        
        # Predict anomaly score
        # decision_function returns negative for outliers, positive for inliers
        # We invert and normalize it roughly to 0-1 range for display
        raw_score = clf.decision_function(features)[0]
        
        # Normalize: decision_function is roughly -0.5 to 0.5
        # We want 1.0 for very anomalous (negative raw score)
        # and 0.0 for very normal (positive raw score)
        norm_score = 0.5 - raw_score
        norm_score = max(0.0, min(1.0, norm_score))
        
        return float(norm_score)
        
    except Exception as e:
        log_error("Anomaly scoring failed", e)
        return 0.0


def classify_anomaly(score: float) -> str:
    """
    Classify anomaly score into human-readable label.
    
    Args:
        score: Anomaly score (0.0-1.0)
        
    Returns:
        Label string
    """
    if score >= 0.7:
        return "highly_anomalous"
    elif score >= 0.4:
        return "risky"
    else:
        return "normal"
