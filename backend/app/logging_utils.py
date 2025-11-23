"""
Structured logging utilities for security events.

Provides JSON-formatted logging for integration with SIEM systems
like ELK Stack, Splunk, or CloudWatch.
"""

import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class SecurityEventLogger:
    """
    Logger for security-relevant events.
    
    Formats events as JSON for easy ingestion by log aggregation systems.
    """
    
    @staticmethod
    def log_qr_scan(
        station_id: Optional[str],
        verdict: str,
        score: int,
        url: str,
        host: Optional[str],
        platform: Optional[str] = None,
        app_version: Optional[str] = None,
        severity: str = "INFO"
    ) -> None:
        """
        Log a QR code scan event.
        
        Args:
            station_id: Station code where scan occurred
            verdict: Security verdict (safe, suspicious, malicious)
            score: Risk score (0-100)
            url: Scanned URL
            host: Extracted hostname
            platform: Device platform (android, ios)
            app_version: Mobile app version
            severity: Log severity (INFO, WARNING, CRITICAL)
        """
        event = {
            "event_type": "qr_scan",
            "timestamp": datetime.utcnow().isoformat(),
            "station_id": station_id,
            "verdict": verdict,
            "score": score,
            "url": url,
            "host": host,
            "platform": platform,
            "app_version": app_version,
        }
        
        log_message = json.dumps(event)
        
        if severity == "CRITICAL" or verdict == "malicious":
            logger.critical(log_message)
        elif severity == "WARNING" or verdict == "suspicious":
            logger.warning(log_message)
        else:
            logger.info(log_message)
    
    @staticmethod
    def log_domain_reputation_change(
        host: str,
        is_official: bool,
        is_denied: bool,
        note: Optional[str] = None
    ) -> None:
        """
        Log changes to domain reputation.
        
        Args:
            host: Domain name
            is_official: Whether domain is marked as official
            is_denied: Whether domain is blocked
            note: Additional notes
        """
        event = {
            "event_type": "domain_reputation_change",
            "timestamp": datetime.utcnow().isoformat(),
            "host": host,
            "is_official": is_official,
            "is_denied": is_denied,
            "note": note,
        }
        
        logger.info(json.dumps(event))


def setup_logging(log_level: str = "INFO") -> None:
    """
    Configure application logging.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
