"""
Typosquatting detection utilities.

Typosquatting is a common phishing technique where attackers register domains
that are very similar to legitimate domains, hoping users won't notice the difference.

Examples:
- official-domain.com → officlal-domain.com (missing 'i')
- official-domain.com → official-domian.com (transposed letters)
- official-domain.com → official-domain-secure.com (added keyword)
- official-domain.com → official-domain.co (different TLD)

Security Impact:
- Users scanning fake QR codes may not notice subtle domain differences
- Attackers use typosquatting for phishing, credential theft, malware distribution
- Critical in QR code scenarios where users don't manually type URLs

This module uses Levenshtein distance to detect suspiciously similar domains.
"""

from typing import List, Tuple

try:
    from rapidfuzz import distance as fuzz_distance
    
    def levenshtein_distance(s1: str, s2: str) -> int:
        """Levenshtein distance using rapidfuzz library."""
        return int(fuzz_distance.Levenshtein.distance(s1, s2))
except ImportError:
    # Fallback implementation if rapidfuzz is not installed
    def levenshtein_distance(s1: str, s2: str) -> int:
        """
        Simple Levenshtein distance implementation.
        
        Calculates the minimum number of single-character edits (insertions,
        deletions, or substitutions) needed to change s1 into s2.
        
        Args:
            s1: First string
            s2: Second string
            
        Returns:
            Edit distance between the two strings
        """
        if len(s1) < len(s2):
            return levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                # Cost of insertions, deletions, or substitutions
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]


def check_typosquatting(
    scanned_host: str,
    official_domains: List[str],
    max_distance: int = 2
) -> Tuple[bool, str | None]:
    """
    Check if a scanned domain is suspiciously similar to official domains.
    
    This function detects potential typosquatting by comparing the scanned
    domain against all known official domains using Levenshtein distance.
    
    Security Rationale:
    - Distance <= 2: Very likely typosquatting (1-2 character changes)
    - Common patterns: missing letters, transposed letters, added keywords
    - In QR scenarios, users rarely scrutinize URLs character-by-character
    
    Args:
        scanned_host: Domain from the scanned QR code
        official_domains: List of legitimate domains to compare against
        max_distance: Maximum edit distance to consider suspicious (default: 2)
        
    Returns:
        Tuple of (is_suspicious, closest_domain)
        - is_suspicious: True if domain matches typosquatting pattern
        - closest_domain: The official domain it's similar to (if any)
        
    Examples:
        >>> check_typosquatting("officlal-domain.com", ["official-domain.com"])
        (True, "official-domain.com")  # Distance: 1 (missing 'i')
        
        >>> check_typosquatting("completely-different.com", ["official-domain.com"])
        (False, None)  # Distance too large
    """
    scanned_host_lower = scanned_host.lower().strip()
    
    for official_domain in official_domains:
        official_domain_lower = official_domain.lower().strip()
        
        # Calculate edit distance
        distance = levenshtein_distance(scanned_host_lower, official_domain_lower)
        
        # If distance is small, likely typosquatting
        if 0 < distance <= max_distance:
            return True, official_domain
        
        # Also check for subdomain typosquatting
        # Example: secure-official-domain.com (adding prefix)
        if (scanned_host_lower.endswith(official_domain_lower) or
            official_domain_lower in scanned_host_lower):
            # If it's not an exact subdomain match, it's suspicious
            # Example: official-domain.com.fake.com is suspicious
            if not scanned_host_lower.endswith(f".{official_domain_lower}"):
                return True, official_domain
    
    return False, None


def check_suspicious_patterns(host: str, official_domains: List[str]) -> List[str]:
    """
    Check for common suspicious domain patterns beyond simple typosquatting.
    
    Patterns checked:
    - Homograph attacks (not implemented yet - requires unicode analysis)
    - Keyword injection (e.g., official-domain-secure.com, verify-official-domain.com)
    - TLD variations (e.g., .co instead of .com)
    
    Args:
        host: Domain to check
        official_domains: List of official domains
        
    Returns:
        List of detected suspicious patterns
    """
    suspicious_patterns = []
    host_lower = host.lower()
    
    # Check for keyword injection patterns
    suspicious_keywords = [
        'secure', 'verify', 'login', 'account', 'auth', 'payment',
        'confirm', 'update', 'validation', 'check', 'official'
    ]
    
    for domain in official_domains:
        domain_lower = domain.lower()
        
        # Check if official domain is embedded with suspicious keywords
        for keyword in suspicious_keywords:
            # Pattern: keyword-official-domain.com
            if f"{keyword}-{domain_lower}" in host_lower:
                suspicious_patterns.append(
                    f"Şüpheli anahtar kelime eklenmesi: '{keyword}' prefix"
                )
            
            # Pattern: official-domain-keyword.com
            domain_base = domain_lower.split('.')[0]
            if domain_base and f"{domain_base}-{keyword}" in host_lower:
                suspicious_patterns.append(
                    f"Şüpheli anahtar kelime eklenmesi: '{keyword}' suffix"
                )
    
    return suspicious_patterns
