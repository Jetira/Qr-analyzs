"""
Enhanced Risk Scoring Service with Multi-Factor Analysis.

This service implements a nuanced risk scoring model that properly handles:
1. Official EV charging domains (minimal risk)
2. Trusted third-party domains like google.com, apple.com (low risk)
3. Unknown/untrusted domains (scored based on multiple risk factors)

WHY THIS FIXES THE GOOGLE.COM FALSE POSITIVE:
- Previous system: ANY domain != OFFICIAL_DOMAIN → high risk
- New system: Classify domains → apply appropriate risk scoring
- Result: google.com is "trusted_third_party" with low baseline risk (5-10 points)
"""
import re
from urllib.parse import urlparse, parse_qs
from typing import Tuple, List
from app.core.config import settings


class RiskScoringService:
    """
    Calculate risk scores for URLs using multiple factors.
    
    Risk Score Range: 0-100
    - 0-30: Low risk
    - 31-60: Medium risk
    - 61-100: High risk
    """
    
    # Suspicious keywords that may indicate phishing/malicious intent
    SUSPICIOUS_KEYWORDS = [
        "login", "password", "verify", "verification", "reset", 
        "token", "otp", "session", "callback", "redirect",
        "bank", "wallet", "payment", "card", "account",
        "signin", "signup", "auth", "authenticate",
        "confirm", "validate", "secure", "update-info"
    ]
    
    # File extensions that may indicate malware downloads
    SUSPICIOUS_EXTENSIONS = [
        ".apk", ".exe", ".dmg", ".pkg", ".deb", ".msi",
        ".bat", ".sh", ".scr", ".vbs", ".jar"
    ]
    
    # Known legitimate app store patterns
    LEGITIMATE_STORE_PATTERNS = [
        r"play\.google\.com/store/apps",
        r"apps\.apple\.com/.*app",
        r"play\.google\.com/(store|apps)"
    ]
    
    def __init__(self):
        self.settings = settings
    
    def analyze_url(self, url: str) -> Tuple[str, int, str, List[str]]:
        """
        Analyze a URL and return category, risk score, risk level, and reasons.
        
        Returns:
            Tuple of (category, risk_score, risk_level, reasons)
            
        Categories:
            - "official": Official EV charging domain
            - "trusted_third_party": Known safe domains (Google, Apple, etc.)
            - "unknown_or_untrusted": All other domains
        """
        reasons = []
        risk_score = 0
        
        # Parse URL
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
            scheme = parsed.scheme.lower()
        except Exception:
            return ("unknown_or_untrusted", 100, "high", ["Invalid or malformed URL"])
        
        # Step 1: Classify domain
        category = self._classify_domain(url, domain)
        
        if category == "official":
            reasons.append(f"Domain matches official EV charging platform ({domain})")
            risk_score = 5  # Minimal baseline risk
            
        elif category == "trusted_third_party":
            trusted_domain = self._get_trusted_domain_name(domain)
            reasons.append(f"Domain is in trusted third-party list ({trusted_domain})")
            risk_score = 10  # Low baseline risk for trusted domains
            
        else:  # unknown_or_untrusted
            reasons.append(f"Domain not recognized as official or trusted ({domain})")
            risk_score = 30  # Moderate baseline for unknown domains
        
        # Step 2: Apply risk factors
        # These factors apply to ALL categories (even trusted ones can have risky paths/params)
        
        # Factor: No TLS (HTTP instead of HTTPS)
        if scheme == "http":
            risk_score += 20
            reasons.append("⚠️ Using insecure HTTP (no encryption)")
        
        # Factor: Direct file download (especially .apk)
        for ext in self.SUSPICIOUS_EXTENSIONS:
            if path.endswith(ext) or query.endswith(ext):
                risk_score += 30
                reasons.append(f"⚠️ Direct binary download detected ({ext})")
                break
        
        # Factor: Suspicious keywords in path or query
        suspicious_found = []
        full_url_lower = url.lower()
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in path or keyword in query:
                suspicious_found.append(keyword)
        
        if suspicious_found:
            risk_score += min(15, len(suspicious_found) * 5)  # Cap at +15
            reasons.append(f"⚠️ Suspicious keywords detected: {', '.join(suspicious_found[:3])}")
        
        # Factor: Long/obfuscated query string
        if len(query) > 200:
            risk_score += 10
            reasons.append("⚠️ Very long query string (possible obfuscation)")
        
        # Factor: Multiple parameters (potential tracking or session hijacking)
        query_params = parse_qs(query)
        if len(query_params) > 10:
            risk_score += 5
            reasons.append(f"Many query parameters ({len(query_params)} params)")
        
        # Step 3: Apply discounts for known-safe patterns
        if self._is_legitimate_app_store(url):
            risk_score = max(0, risk_score - 20)
            reasons.append("✓ Legitimate app store URL pattern detected")
        
        # Step 4: Cap score at 100
        risk_score = min(100, max(0, risk_score))
        
        # Step 5: Determine risk level
        risk_level = self.settings.get_risk_level(risk_score)
        
        # Add final verdict reason
        if risk_level == "low":
            reasons.append(f"✓ Overall risk assessment: LOW (score: {risk_score}/100)")
        elif risk_level == "medium":
            reasons.append(f"⚠️ Overall risk assessment: MEDIUM (score: {risk_score}/100)")
        else:
            reasons.append(f"🚫 Overall risk assessment: HIGH (score: {risk_score}/100)")
        
        return (category, risk_score, risk_level, reasons)
    
    def _classify_domain(self, url: str, domain: str) -> str:
        """Classify domain into official, trusted, or unknown."""
        # Check official domain
        if self.settings.is_official_domain(url):
            return "official"
        
        # Check trusted third parties
        if self.settings.is_trusted_third_party(domain):
            return "trusted_third_party"
        
        return "unknown_or_untrusted"
    
    def _get_trusted_domain_name(self, domain: str) -> str:
        """Get the friendly name of the trusted domain."""
        domain_lower = domain.lower().replace("www.", "")
        
        # Map to friendly names
        friendly_names = {
            "google.com": "Google",
            "play.google.com": "Google Play Store",
            "apple.com": "Apple",
            "apps.apple.com": "Apple App Store",
            "github.com": "GitHub",
            "stackoverflow.com": "Stack Overflow",
        }
        
        for trusted in self.settings.TRUSTED_THIRD_PARTIES:
            trusted_clean = trusted.lower().replace("www.", "")
            if domain_lower == trusted_clean or domain_lower.endswith(f".{trusted_clean}"):
                return friendly_names.get(trusted_clean, trusted)
        
        return domain
    
    def _is_legitimate_app_store(self, url: str) -> bool:
        """Check if URL matches known legitimate app store patterns."""
        for pattern in self.LEGITIMATE_STORE_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False
    
    def get_recommended_action(self, risk_level: str, category: str) -> str:
        """
        Get recommended action based on risk level and category.
        
        Returns: "allow", "warn", or "block"
        """
        if category == "official":
            return "allow" if risk_level == "low" else "warn"
        
        if category == "trusted_third_party":
            if risk_level == "low":
                return "allow"
            elif risk_level == "medium":
                return "warn"
            else:
                return "block"
        
        # unknown_or_untrusted
        if risk_level == "low":
            return "warn"  # Still warn for unknown domains even if low risk
        elif risk_level == "medium":
            return "warn"
        else:
            return "block"
    
    def get_user_friendly_verdict(self, category: str, risk_level: str, domain: str) -> str:
        """Generate a user-friendly verdict message."""
        if category == "official":
            return f"✓ This is the official EV charging platform"
        
        if category == "trusted_third_party":
            domain_name = self._get_trusted_domain_name(domain)
            if risk_level == "low":
                return f"✓ This is a well-known, legitimate website ({domain_name})"
            else:
                return f"⚠️ This is {domain_name}, but the specific URL has suspicious elements"
        
        # unknown_or_untrusted
        if risk_level == "low":
            return "This domain is not recognized, but shows no obvious signs of being malicious"
        elif risk_level == "medium":
            return "⚠️ This URL shows some suspicious characteristics. Proceed with caution"
        else:
            return "🚫 This URL appears to be malicious or highly suspicious. Do not proceed"


# Global instance
risk_scorer = RiskScoringService()
