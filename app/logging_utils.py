"""
Structured logging utilities for QR Security Service.

Provides helper functions for logging security events with consistent formatting.
Uses Python's built-in logging module with structured fields for easy parsing.
"""

import logging
from typing import Any, Dict, Optional

# Configure logging format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger("qr_security")


def log_qr_scan_attempt(
    station_id: Optional[str],
    raw_qr_data: str,
    verdict: str,
    score: int,
    host: Optional[str] = None,
    reasons: Optional[list] = None,
    app_version: Optional[str] = None,
    platform: Optional[str] = None
) -> None:
    """
    Log a QR code scan attempt with structured data.
    
    Security Importance:
    - Provides audit trail for forensic analysis
    - Helps detect attack patterns (e.g., multiple malicious scans)
    - Enables incident response and threat intelligence
    - Logs are critical for compliance and security monitoring
    
    Args:
        station_id: Station where QR was scanned
        raw_qr_data: Raw QR content (may contain malicious data)
        verdict: Risk verdict (safe/suspicious/malicious)
        score: Risk score (0-100)
        host: Hostname from URL (if applicable)
        reasons: List of security issues detected
        app_version: Mobile app version
        platform: Client platform (android/ios)
    """
    # Build structured log message
    log_data: Dict[str, Any] = {
        "event": "qr_scan",
        "station_id": station_id,
        "verdict": verdict,
        "score": score,
        "host": host,
        "app_version": app_version,
        "platform": platform,
    }
    
    # Truncate QR data for log readability (avoid logging very long payloads)
    qr_data_preview = raw_qr_data[:200] + "..." if len(raw_qr_data) > 200 else raw_qr_data
    log_data["qr_data_preview"] = qr_data_preview
    
    if reasons:
        log_data["reasons"] = reasons
    
    # Choose log level based on verdict
    if verdict == "malicious":
        # High-severity logs for malicious QR codes
        logger.warning(
            f"🚨 MALICIOUS QR detected | Station: {station_id} | Host: {host} | "
            f"Score: {score} | Reasons: {reasons}",
            extra=log_data
        )
    elif verdict == "suspicious":
        # Medium-severity logs for suspicious QR codes
        logger.info(
            f"⚠️  SUSPICIOUS QR detected | Station: {station_id} | Host: {host} | "
            f"Score: {score} | Reasons: {reasons}",
            extra=log_data
        )
    else:
        # Low-severity logs for safe QR codes
        logger.info(
            f"✅ SAFE QR scanned | Station: {station_id} | Host: {host}",
            extra=log_data
        )


def log_domain_reputation_update(
    host: str,
    is_official: bool,
    is_denied: bool,
    action: str = "created"
) -> None:
    """
    Log updates to domain reputation database.
    
    Args:
        host: Domain being updated
        is_official: Whether marked as official
        is_denied: Whether marked as denied
        action: Type of action (created/updated)
    """
    status = "OFFICIAL" if is_official else ("DENIED" if is_denied else "NEUTRAL")
    logger.info(
        f"Domain reputation {action}: {host} → {status}",
        extra={
            "event": "domain_reputation_update",
            "host": host,
            "is_official": is_official,
            "is_denied": is_denied,
            "action": action
        }
    )


def log_error(message: str, error: Exception, context: Optional[Dict[str, Any]] = None) -> None:
    """
    Log an error with context information.
    
    Args:
        message: Error description
        error: Exception object
        context: Additional context data
    """
    extra_data = {"event": "error", "error_type": type(error).__name__}
    if context:
        extra_data.update(context)
    
    logger.error(
        f"{message}: {str(error)}",
        exc_info=True,
        extra=extra_data
    )
