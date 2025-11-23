"""
QR Code Analysis Service.

This is the core security module that analyzes QR code content and determines risk level.

Security Analysis Components:
1. HTTPS Enforcement - Detect unencrypted connections (MITM risk)
2. Domain Allowlist - Verify against official domains
3. Typosquatting Detection - Identify fake domains similar to official ones
4. Malicious File Detection - Flag potentially harmful downloads
5. Redirect Risk Assessment - Detect open redirect vulnerabilities
"""

from typing import List, Tuple, Optional, Any
from urllib.parse import urlparse, parse_qs
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.schemas_legacy import QRAnalyzeResponse
from app.models_legacy import DomainReputation
from app.core.config import Settings

# ==========================================
# HELPER FUNCTIONS
# ==========================================

async def get_domain_reputation(host: str, db: AsyncSession) -> Tuple[bool, bool]:
    """
    Check domain reputation in database.
    Returns: (is_official, is_denied)
    """
    try:
        result = await db.execute(
            select(DomainReputation).where(DomainReputation.host == host)
        )
        domain_record = result.scalars().first()
        
        if domain_record:
            return (domain_record.is_official, domain_record.is_denied)
        return (False, False)
    except Exception:
        return (False, False)

def check_typosquatting(host: str, official_domains: List[str]) -> Tuple[bool, str]:
    """
    Check if host looks very similar to an official domain (typosquatting).
    """
    if not host:
        return False, ""
        
    host_clean = host.lower().replace("www.", "")
    
    for official in official_domains:
        official_clean = official.lower().replace("www.", "")
        
        # Skip if exact match (handled by allowlist)
        if host_clean == official_clean:
            continue
            
        # Simple Levenshtein-like check:
        # If length difference is small and common chars are high
        if abs(len(host_clean) - len(official_clean)) <= 2:
            # Count matching chars
            matches = 0
            for c1, c2 in zip(host_clean, official_clean):
                if c1 == c2:
                    matches += 1
            
            # If > 80% match but not identical
            if matches / max(len(host_clean), len(official_clean)) > 0.8:
                return True, official
                
    return False, ""

def check_suspicious_patterns(host: str, official_domains: List[str]) -> List[str]:
    """
    Check for suspicious keywords in the domain.
    """
    suspicious_keywords = ["login", "secure", "account", "update", "verify", "wallet", "bank"]
    reasons = []
    
    host_lower = host.lower()
    for keyword in suspicious_keywords:
        if keyword in host_lower:
            # If keyword is in domain but it's NOT an official domain
            is_official = any(d in host_lower for d in official_domains)
            if not is_official:
                reasons.append(f"Domain şüpheli anahtar kelime içeriyor: '{keyword}'")
                
    return reasons

def verify_dynamic_qr_token(token: str) -> bool:
    """
    Verify if the dynamic QR token is valid.
    Placeholder for actual cryptographic verification.
    """
    # In a real app, this would verify a JWT or HMAC
    if not token:
        return False
    # Simulate validation: tokens longer than 10 chars are "valid" for this demo
    return len(token) > 10

def get_ml_model(settings: Any) -> Any:
    """Placeholder for ML model loading"""
    return None

def ml_score_url(url: str, official_domains: List[str], model: Any) -> Tuple[Optional[float], Optional[str]]:
    """Placeholder for ML scoring"""
    return None, None


# ==========================================
# MAIN ANALYSIS FUNCTION
# ==========================================

async def analyze_url(
    url: str,
    settings: Settings,
    db: AsyncSession
) -> QRAnalyzeResponse:
    """
    Analyze a URL and determine its risk level.
    
    Args:
        url: The URL to analyze
        settings: Application settings (contains official domains)
        db: Database session for reputation lookups
        
    Returns:
        QRAnalyzeResponse with verdict, score, reasons, and metadata
    """
    # Initialize risk tracking
    risk_score = 0
    reasons: List[str] = []
    
    # Parse URL
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        host = parsed.hostname or ""
        path = parsed.path
        query = parsed.query
    except Exception:
        # Failed to parse - treat as very suspicious
        return QRAnalyzeResponse(
            verdict="suspicious",
            score=60,
            reasons=["URL parse hatası - geçersiz format"],
            normalized_url=url,
            host=None
        )
    
    # Normalize URL for response
    normalized_url = url.strip().lower()
    
    # ==========================================
    # SECURITY CHECK 1: HTTPS Enforcement
    # ==========================================
    if scheme != "https":
        reasons.append("HTTPS değil - şifrelenmemiş bağlantı (MITM riski)")
        risk_score += 60
    
    # ==========================================
    # SECURITY CHECK 2: Domain Reputation Check
    # ==========================================
    is_official_db, is_denied_db = await get_domain_reputation(host, db)
    
    if is_denied_db:
        reasons.append("Bilinen zararlı domain (blacklist)")
        risk_score += 80
    
    # Use TRUSTED_THIRD_PARTIES from settings as official/trusted list
    official_domains = settings.TRUSTED_THIRD_PARTIES + [settings.OFFICIAL_DOMAIN]
    is_in_allowlist = False
    
    for official_domain in official_domains:
        # Clean domain for comparison
        clean_official = official_domain.replace("https://", "").replace("http://", "").split("/")[0]
        if host == clean_official or host.endswith(f".{clean_official}"):
            is_in_allowlist = True
            break
    
    if is_official_db:
        is_in_allowlist = True
    
    # Common well-known trusted domains (to avoid false positives)
    common_trusted_domains = [
        'google.com', 'youtube.com', 'facebook.com', 'instagram.com', 
        'twitter.com', 'linkedin.com', 'microsoft.com', 'apple.com',
        'amazon.com', 'wikipedia.org', 'github.com'
    ]
    
    is_common_trusted = any(host == domain or host.endswith(f".{domain}") 
                           for domain in common_trusted_domains)
    
    # Only add risk if domain is NOT in allowlist AND NOT a common trusted site
    if not is_in_allowlist and not is_denied_db and not is_common_trusted:
        reasons.append("Resmi domain değil - bilinmeyen kaynak")
        risk_score += 40
    
    # ==========================================
    # SECURITY CHECK 3: Typosquatting Detection
    # ==========================================
    is_typosquatting, similar_domain = check_typosquatting(host, official_domains)
    
    if is_typosquatting:
        reasons.append(f"Resmi domaine çok benzer (typosquatting şüphesi: '{similar_domain}')")
        risk_score += 50
    
    suspicious_patterns = check_suspicious_patterns(host, official_domains)
    if suspicious_patterns:
        reasons.extend(suspicious_patterns)
        risk_score += 30
    
    # ==========================================
    # SECURITY CHECK 4: Malicious File Extensions
    # ==========================================
    malicious_extensions = ['.apk', '.exe', '.msi', '.bat', '.scr', '.zip', '.jar']
    
    if any(path.lower().endswith(ext) for ext in malicious_extensions):
        file_ext = next(ext for ext in malicious_extensions if path.lower().endswith(ext))
        reasons.append(f"Potansiyel zararlı dosya indirme ({file_ext}) - malware riski")
        risk_score += 80
    
    # ==========================================
    # SECURITY CHECK 5: Dynamic Redirect Risk
    # ==========================================
    redirect_params = ['url', 'redirect', 'target', 'next', 'return', 'goto', 'redir']
    
    if query:
        parsed_qs = parse_qs(query)
        for param in redirect_params:
            if param in parsed_qs:
                redirect_target = parsed_qs[param][0] if parsed_qs[param] else ""
                if redirect_target and ('://' in redirect_target or redirect_target.startswith('//')):
                    reasons.append(f"Dış domaine yönlendirme parametresi ({param}=...) - phishing riski")
                    risk_score += 40
                    break
    
    # ==========================================
    # SECURITY CHECK 6: Machine Learning Analysis
    # ==========================================
    # (Skipped for this version as ML model is not loaded)

    # ==========================================
    # SECURITY CHECK 7: Dynamic QR Token Validation
    # ==========================================
    token = None
    if query:
        parsed_qs = parse_qs(query)
        if 'token' in parsed_qs:
            token = parsed_qs['token'][0]
            
    if token:
        is_valid_token = verify_dynamic_qr_token(token)
        if is_valid_token:
            reasons.append("Dinamik QR Token Doğrulandı ✅")
            risk_score = max(0, risk_score - 20)
        else:
            reasons.append("GEÇERSİZ veya SÜRESİ DOLMUŞ Token ❌")
            risk_score += 50
    
    # ==========================================
    # RISK SCORE FINALIZATION
    # ==========================================
    risk_score = max(0, min(100, risk_score))
    
    if risk_score >= 80:
        verdict = "malicious"
    elif risk_score >= 40:
        verdict = "suspicious"
    else:
        verdict = "safe"
    
    if not reasons:
        reasons.append("Güvenlik kontrolleri başarılı")
    
    return QRAnalyzeResponse(
        verdict=verdict,
        score=risk_score,
        reasons=reasons,
        normalized_url=normalized_url,
        host=host
    )
