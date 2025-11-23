"""
JWT Utilities for Dynamic QR Codes.

Handles generation and verification of signed QR tokens.
"""

import time
from typing import Dict, Optional

import jwt

# SECRET KEY for signing tokens
# In production, this should be loaded from environment variables/secrets manager
# and rotated regularly.
JWT_SECRET_KEY = "charge-sentinel-super-secret-key-change-in-production"
JWT_ALGORITHM = "HS256"

def generate_dynamic_qr_token(station_id: str, valid_minutes: int = 5) -> str:
    """
    Generate a signed JWT token for a specific station.
    
    Args:
        station_id: UUID of the station
        valid_minutes: How long the token is valid (default 5 mins)
        
    Returns:
        Encoded JWT string
    """
    payload = {
        "iss": "qr-security-service",
        "sub": "station-qr",
        "station_id": station_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + (valid_minutes * 60),
        "nonce": str(time.time())  # Simple nonce
    }
    
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token


def decode_and_verify_token(token: str) -> Optional[Dict]:
    """
    Decode and verify a JWT token.
    
    Args:
        token: JWT string
        
    Returns:
        Decoded payload dict if valid, None if invalid/expired
    """
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            issuer="qr-security-service"
        )
        return payload
    except jwt.ExpiredSignatureError:
        print("[JWT] Token expired")
        return None
    except jwt.InvalidTokenError as e:
        print(f"[JWT] Invalid token: {e}")
        return None
