"""
Helper script to generate Dynamic QR Tokens for testing.
"""

import sys
import os

# Add project root to path so we can import app modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.security.jwt_utils import generate_dynamic_qr_token

def main():
    print("🔐 Dynamic QR Token Generator")
    print("-" * 30)
    
    station_id = "550e8400-e29b-41d4-a716-446655440000"
    
    # 1. Valid Token
    token_valid = generate_dynamic_qr_token(station_id, valid_minutes=5)
    print(f"\n✅ GEÇERLİ TOKEN (5 dk):")
    print(f"{token_valid}")
    
    # 2. Expired Token (created 10 mins ago, valid for 5 mins)
    # We can't easily mock time in the generator without modifying it, 
    # so we'll just generate a short lived one for now.
    # Or we can manually create an expired one here using the same secret.
    import jwt
    import time
    expired_payload = {
        "iss": "qr-security-service",
        "sub": "station-qr",
        "station_id": station_id,
        "iat": int(time.time()) - 600,
        "exp": int(time.time()) - 300, # Expired 5 mins ago
        "nonce": "expired"
    }
    token_expired = jwt.encode(expired_payload, "charge-sentinel-super-secret-key-change-in-production", algorithm="HS256")
    
    print(f"\n❌ SÜRESİ DOLMUŞ TOKEN:")
    print(f"{token_expired}")
    
    print("\n" + "-" * 30)
    print("Test etmek için bu tokenları kullanabilirsiniz.")
    print("Not: Şu anki API implementation'ı URL içinde 'token' parametresi arıyor mu?")
    print("Kontrol edelim: qr_analyzer.py içinde henüz token parametresini URL'den ayıklayan kod yok.")
    print("Bu özelliği tam test etmek için URL'e ?token=... ekleyip analizörde bunu kontrol etmeliyiz.")

if __name__ == "__main__":
    main()
