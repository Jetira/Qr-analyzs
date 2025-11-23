"""
QR Code Analysis Service.

Core security analysis engine for detecting malicious QR codes in EV charging stations.

Implements five security rules:
1. HTTPS Enforcement - Prevents MITM attacks
2. Official Domain Allowlist - Blocks unauthorized domains
3. Typosquatting Detection - Catches similar-looking domains
4. Malicious File Extensions - Prevents malware downloads
5. Dynamic Redirect Detection - Flags open redirect vulnerabilities

Risk Scoring System:
- Each rule contributes points when triggered
- Total score maps to verdict: safe (<40), suspicious (40-79), malicious (≥80)
- Provides transparency via human-readable reasons
"""

from typing import List, Optional
from urllib.parse import urlparse, parse_qs
import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.models import DomainReputation
from app.schemas import QRAnalyzeResponse
from app.security.typosquatting import check_typosquatting

logger = logging.getLogger(__name__)


# ============================================================================
# Risk Score Constants
# ============================================================================

# Risk points assigned for each security rule violation
RISK_POINTS = {
    "NO_HTTPS": 60,              # HTTP instead of HTTPS
    "UNOFFICIAL_DOMAIN": 40,     # Domain not in allowlist
    "TYPOSQUATTING": 30,         # Similar to official domain
    "MALICIOUS_FILE": 80,        # APK, EXE, or other dangerous file
    "REDIRECT_PARAM": 20,        # URL contains redirect parameters
}

# Verdict thresholds
VERDICT_THRESHOLDS = {
    "MALICIOUS": 80,    # score >= 80
    "SUSPICIOUS": 40,   # 40 <= score < 80
    # score < 40 is "safe"
}

# File extensions considered potentially malicious
DANGEROUS_EXTENSIONS = [
    ".apk",   # Android package - can install malware
    ".ipa",   # iOS package - requires sideloading
    ".exe",   # Windows executable
    ".msi",   # Windows installer
    ".bat",   # Batch script
    ".cmd",   # Command script
    ".sh",    # Shell script
    ".zip",   # Archive that may contain malware
    ".rar",   # Archive format
    ".7z",    # Archive format
    ".jar",   # Java archive - can execute code
    ".dmg",   # macOS disk image
]


# ============================================================================
# Helper Functions
# ============================================================================

async def get_domain_reputation(
    host: str, 
    db: AsyncSession
) -> Optional[DomainReputation]:
    """
    Query the DomainReputation table for a specific host.
    
    Args:
        host: Domain name to look up
        db: Database session
    
    Returns:
        DomainReputation record if found, None otherwise
    """
    result = await db.execute(
        select(DomainReputation).where(DomainReputation.host == host.lower())
    )
    return result.scalar_one_or_none()


def is_official_domain(host: str, official_domains: List[str]) -> bool:
    """
    Check if a domain is in the official allowlist.
    
    Checks for:
    1. Exact match (case-insensitive)
    2. Subdomain of official domain (e.g., api.official-domain.com)
    
    Args:
        host: Domain to check
        official_domains: List of trusted domains
    
    Returns:
        True if domain is official, False otherwise
    
    Security Note:
    Subdomain matching uses endswith() which requires the official domain
    to have a leading dot to prevent partial matches.
    Example: "evil-official-domain.com" won't match "official-domain.com"
    """
    host_lower = host.lower().strip()
    
    for official in official_domains:
        official_lower = official.lower().strip()
        
        # Exact match
        if host_lower == official_lower:
            return True
        
        # Subdomain match (e.g., api.official-domain.com matches official-domain.com)
        if host_lower.endswith(f".{official_lower}"):
            return True
    
    return False


def check_https(url_parsed) -> tuple[bool, int, str]:
    """
    Rule 1: HTTPS Enforcement
    
    Security Rationale:
    HTTP connections are unencrypted and vulnerable to man-in-the-middle attacks.
    In payment and authentication scenarios, HTTPS is mandatory to:
    - Protect credentials in transit
    - Prevent session hijacking
    - Ensure data integrity
    
    Args:
        url_parsed: Parsed URL object from urllib.parse
    
    Returns:
        Tuple of (is_violation, risk_points, reason)
    """
    if url_parsed.scheme != "https":
        return True, RISK_POINTS["NO_HTTPS"], "HTTPS değil (güvenli bağlantı yok)"
    return False, 0, ""


async def check_domain_allowlist(
    host: str,
    official_domains: List[str],
    db: AsyncSession
) -> tuple[bool, int, str]:
    """
    Rule 2: Official Domain Allowlist
    
    Security Rationale:
    Only company-controlled domains should be used for official QR codes.
    This prevents:
    - Phishing attacks using attacker-controlled domains
    - Data exfiltration to third-party servers
    - Credential theft via fake login pages
    
    Checks both:
    1. Configuration-based allowlist (OFFICIAL_DOMAINS env var)
    2. Database-based reputation (DomainReputation table)
    
    Args:
        host: Domain to validate
        official_domains: List from configuration
        db: Database session
    
    Returns:
        Tuple of (is_violation, risk_points, reason)
    """
    # Check configuration allowlist
    if is_official_domain(host, official_domains):
        return False, 0, ""
    
    # Check database reputation
    reputation = await get_domain_reputation(host, db)
    
    if reputation:
        # Explicitly denied domain
        if reputation.is_denied:
            return True, RISK_POINTS["UNOFFICIAL_DOMAIN"] + 40, \
                   f"Domain '{host}' engelleme listesinde (bilinen phishing)"
        
        # Explicitly allowed domain
        if reputation.is_official:
            return False, 0, ""
    
    # Domain not in allowlist
    return True, RISK_POINTS["UNOFFICIAL_DOMAIN"], \
           f"Resmi domain listesinde değil: '{host}'"


def check_typosquatting_risk(
    host: str,
    official_domains: List[str]
) -> tuple[bool, int, List[str]]:
    """
    Rule 3: Typosquatting Detection
    
    Security Rationale:
    Attackers register domains visually similar to official domains.
    Users scanning QR codes quickly may not notice subtle differences.
    
    Examples:
    - Character substitution: official → officia1 (l → 1)
    - Extra keywords: official-domain.com → official-domain-pay.com
    - TLD swaps: .com → .net, .org
    
    Args:
        host: Domain to check
        official_domains: List of legitimate domains
    
    Returns:
        Tuple of (is_violation, risk_points, reasons_list)
    """
    is_typosquat, closest_match, typo_reasons = check_typosquatting(
        host, 
        official_domains,
        distance_threshold=2
    )
    
    if is_typosquat:
        formatted_reasons = [
            f"Resmi domaine çok benzer (typosquatting şüphesi): {reason}"
            for reason in typo_reasons
        ]
        return True, RISK_POINTS["TYPOSQUATTING"], formatted_reasons
    
    return False, 0, []


def check_malicious_files(url_path: str) -> tuple[bool, int, str]:
    """
    Rule 4: Malicious File Extensions
    
    Security Rationale:
    QR codes should link to web pages, not file downloads.
    File downloads enable:
    - Malware installation (APK sideloading, EXE execution)
    - Zero-day exploits via archive extraction
    - Credential theft via fake app clones
    
    Exception (noted in code, not enforced):
    Official app stores (Google Play, Apple App Store) could be allowed
    for legitimate app updates. For now, we block all file downloads.
    
    Args:
        url_path: URL path component
    
    Returns:
        Tuple of (is_violation, risk_points, reason)
    """
    path_lower = url_path.lower()
    
    for ext in DANGEROUS_EXTENSIONS:
        if path_lower.endswith(ext):
            return True, RISK_POINTS["MALICIOUS_FILE"], \
                   f"Potansiyel zararlı dosya indirme tespit edildi ({ext.upper()})"
    
    return False, 0, ""


def check_redirect_parameters(query_params: dict) -> tuple[bool, int, str]:
    """
    Rule 5: Dynamic Redirect Detection
    
    Security Rationale:
    URL parameters like ?redirect= enable open redirect vulnerabilities.
    Attackers can craft URLs that:
    1. Start with official domain (passes initial checks)
    2. Redirect to attacker domain (after user interaction)
    
    Example attack:
    https://official-domain.com/login?redirect=https://phishing-site.com
    
    Note: This is a simplified check. A full implementation would:
    - Parse the redirect URL
    - Validate the redirect destination
    - Check if it's to an official domain
    
    Args:
        query_params: Parsed query parameters from URL
    
    Returns:
        Tuple of (is_violation, risk_points, reason)
    """
    redirect_param_names = ["redirect", "url", "target", "next", "return", "goto"]
    
    for param_name in redirect_param_names:
        if param_name in query_params:
            return True, RISK_POINTS["REDIRECT_PARAM"], \
                   f"Dış domaine yönlendirme parametresi içeriyor ('{param_name}')"
    
    return False, 0, ""


def calculate_verdict(score: int) -> str:
    """
    Map risk score to security verdict.
    
    Scoring Logic:
    - 0-39: Safe (low risk, likely legitimate)
    - 40-79: Suspicious (medium risk, needs user warning)
    - 80-100: Malicious (high risk, should be blocked)
    
    Args:
        score: Total risk score (0-100)
    
    Returns:
        Verdict string: "safe", "suspicious", or "malicious"
    """
    if score >= VERDICT_THRESHOLDS["MALICIOUS"]:
        return "malicious"
    elif score >= VERDICT_THRESHOLDS["SUSPICIOUS"]:
        return "suspicious"
    else:
        return "safe"


# ============================================================================
# JWT Dynamic QR Validation (Placeholder)
# ============================================================================

def verify_dynamic_qr_token(token: str) -> bool:
    """
    PLACEHOLDER: Future JWT-based dynamic QR validation.
    
    Concept:
    Official QR codes can embed a JWT token that is:
    1. Generated by the backend when printing QR stickers
    2. Contains: station_id, expiration timestamp, nonce
    3. Signed with server's private key
    
    Validation flow:
    1. Extract JWT from QR data (e.g., as query parameter)
    2. Verify signature using public key
    3. Check expiration (exp claim)
    4. Verify nonce hasn't been used (replay protection)
    5. Match station_id with claimed station
    
    Benefits:
    - Prevents physical QR replacement (attackers can't forge valid JWTs)
    - Enables QR expiration (old stickers become invalid)
    - Provides cryptographic proof of authenticity
    
    Implementation:
    Use PyJWT library to encode/decode tokens.
    Store nonces in Redis for replay detection.
    
    Args:
        token: JWT string from QR code
    
    Returns:
        True if token is valid, False otherwise
    
    TODO: Implement full JWT validation logic
    """
    # Placeholder implementation
    logger.info(f"JWT validation not yet implemented. Token: {token[:20]}...")
    return False


# ============================================================================
# Main Analysis Function
# ============================================================================

async def analyze_url(
    url: str,
    settings: Settings,
    db: AsyncSession
) -> QRAnalyzeResponse:
    """
    Analyze a URL from a QR code and determine its security risk.
    
    Applies five security rules and aggregates risk scores:
    1. HTTPS Enforcement (+60 if violated)
    2. Official Domain Allowlist (+40 if violated)
    3. Typosquatting Detection (+30 if detected)
    4. Malicious File Extensions (+80 if detected)
    5. Dynamic Redirect Parameters (+20 if detected)
    
    Args:
        url: URL extracted from QR code
        settings: Application settings (official domains, etc.)
        db: Database session for reputation lookup
    
    Returns:
        QRAnalyzeResponse with verdict, score, and reasons
    
    Example:
        >>> response = await analyze_url(
        ...     "http://fake-domain.com/charge.apk",
        ...     settings,
        ...     db
        ... )
        >>> response.verdict
        "malicious"
        >>> response.score
        180  # Clamped to 100
    """
    reasons: List[str] = []
    score = 0
    
    # Parse the URL
    parsed = urlparse(url)
    host = parsed.netloc.lower() if parsed.netloc else ""
    
    # ========================================================================
    # Rule 1: HTTPS Enforcement
    # ========================================================================
    is_http_violation, http_points, http_reason = check_https(parsed)
    if is_http_violation:
        score += http_points
        reasons.append(http_reason)
    
    # ========================================================================
    # Rule 2: Official Domain Allowlist
    # ========================================================================
    if host:  # Only check if we have a valid host
        is_domain_violation, domain_points, domain_reason = await check_domain_allowlist(
            host,
            settings.official_domains_list,
            db
        )
        if is_domain_violation:
            score += domain_points
            reasons.append(domain_reason)
    
    # ========================================================================
    # Rule 3: Typosquatting Detection
    # ========================================================================
    if host:
        is_typo, typo_points, typo_reasons = check_typosquatting_risk(
            host,
            settings.official_domains_list
        )
        if is_typo:
            score += typo_points
            reasons.extend(typo_reasons)
    
    # ========================================================================
    # Rule 4: Malicious File Extensions
    # ========================================================================
    is_file_violation, file_points, file_reason = check_malicious_files(parsed.path)
    if is_file_violation:
        score += file_points
        reasons.append(file_reason)
    
    # ========================================================================
    # Rule 5: Dynamic Redirect Parameters
    # ========================================================================
    query_params = parse_qs(parsed.query)
    is_redirect_violation, redirect_points, redirect_reason = check_redirect_parameters(
        query_params
    )
    if is_redirect_violation:
        score += redirect_points
        reasons.append(redirect_reason)
    
    # ========================================================================
    # Calculate Final Verdict
    # ========================================================================
    
    # Clamp score to 0-100 range
    score = max(0, min(100, score))
    
    # Determine verdict based on score
    verdict = calculate_verdict(score)
    
    # If no violations found, add a positive reason
    if not reasons:
        reasons.append("Güvenli görünüyor: HTTPS kullanılıyor ve resmi domain listesinde")
    
    return QRAnalyzeResponse(
        verdict=verdict,
        score=score,
        reasons=reasons,
        normalized_url=url,
        host=host if host else None
    )
