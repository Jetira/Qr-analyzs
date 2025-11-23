"""
Notification Service.

Handles sending alerts for critical security events (e.g., malicious QR scans).
Supports:
- Structured Logging (always on)
- Slack Webhooks (optional, if configured)
"""

import json
from datetime import datetime

import httpx

from app.config import get_settings
from app.logging_utils import log_error

settings = get_settings()


async def send_slack_alert(
    station_code: str,
    verdict: str,
    score: int,
    url: str,
    reasons: list[str]
):
    """
    Send a formatted alert to Slack via Webhook.
    """
    if not settings.SLACK_WEBHOOK_URL:
        return

    color = "#ff0000" if verdict == "malicious" else "#ffcc00"
    
    payload = {
        "attachments": [
            {
                "color": color,
                "pretext": "🚨 *QR Güvenlik Uyarısı*",
                "fields": [
                    {"title": "İstasyon", "value": station_code, "short": True},
                    {"title": "Risk Skoru", "value": str(score), "short": True},
                    {"title": "Karar", "value": verdict.upper(), "short": True},
                    {"title": "URL", "value": url, "short": False},
                    {"title": "Tespitler", "value": "\n".join(f"• {r}" for r in reasons), "short": False}
                ],
                "footer": "ChargeSentinel Security",
                "ts": int(datetime.now().timestamp())
            }
        ]
    }

    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                settings.SLACK_WEBHOOK_URL,
                json=payload,
                timeout=5.0
            )
    except Exception as e:
        log_error("Slack bildirimi gönderilemedi", e)


async def notify_security_event(
    station_id: str,
    verdict: str,
    score: int,
    url: str,
    reasons: list[str]
):
    """
    Central notification handler.
    Called as a BackgroundTask to avoid blocking the API response.
    """
    # 1. Always log to console/file (already handled by logging_utils, but adding a high-vis alert here)
    if verdict == "malicious":
        print(f"\n{'!'*50}")
        print(f"🚨 KRİTİK GÜVENLİK UYARISI - İstasyon: {station_id}")
        print(f"   URL: {url}")
        print(f"   Skor: {score}")
        print(f"   Nedenler: {reasons}")
        print(f"{'!'*50}\n")

    # 2. Send Slack Alert if configured
    if verdict in ["malicious", "suspicious"]:
        # In a real app, we would fetch the station_code from DB using station_id
        # For now, we'll just use the ID or a placeholder
        await send_slack_alert(
            station_code=f"Station-{station_id[:8]}...", # Truncated ID for display
            verdict=verdict,
            score=score,
            url=url,
            reasons=reasons
        )
