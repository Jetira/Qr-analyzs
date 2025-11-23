"""
Typosquatting detection module.

Detects domain similarity attacks where attackers register domains that look
similar to official domains to trick users.

Examples of typosquatting:
- Character substitution: official-domain.com → officia1-domain.com (l → 1)
- Extra characters: official-domain.com → official-domain-pay.com
- TLD variations: official-domain.com → official-domain.net
- Homograph attacks: official-domain.com → оfficial-domain.com (Cyrillic 'о')

Security Impact:
In the QR phishing scenario, attackers print fake QR stickers with typosquatted
domains. Users who don't carefully inspect URLs will trust the similar-looking domain.
"""

from typing import List, Tuple, Optional


def calculate_levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculate Levenshtein distance between two strings.
    
    Levenshtein distance is the minimum number of single-character edits
    (insertions, deletions, or substitutions) required to change one string
    into another.
    
    Algorithm: Dynamic programming with O(m*n) time and space complexity.
    
    Args:
        s1: First string
        s2: Second string
    
    Returns:
        int: Edit distance between the strings
    
    Example:
        >>> calculate_levenshtein_distance("kitten", "sitting")
        3  # k→s, e→i, insert g
        >>> calculate_levenshtein_distance("official", "officia1")
        1  # l→1
    """
    len1, len2 = len(s1), len(s2)
    
    # Create a matrix to store distances
    # dp[i][j] = distance between s1[:i] and s2[:j]
    dp = [[0] * (len2 + 1) for _ in range(len1 + 1)]
    
    # Initialize base cases
    for i in range(len1 + 1):
        dp[i][0] = i  # Distance from s1[:i] to empty string
    for j in range(len2 + 1):
        dp[0][j] = j  # Distance from empty string to s2[:j]
    
    # Fill the matrix using dynamic programming
    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            if s1[i-1] == s2[j-1]:
                # Characters match, no edit needed
                dp[i][j] = dp[i-1][j-1]
            else:
                # Take minimum of:
                # - Substitution: dp[i-1][j-1] + 1
                # - Deletion: dp[i-1][j] + 1
                # - Insertion: dp[i][j-1] + 1
                dp[i][j] = 1 + min(
                    dp[i-1][j-1],  # Substitution
                    dp[i-1][j],    # Deletion
                    dp[i][j-1]     # Insertion
                )
    
    return dp[len1][len2]


def detect_suspicious_patterns(domain: str, official_domain: str) -> List[str]:
    """
    Detect common typosquatting patterns beyond edit distance.
    
    Patterns checked:
    1. Official domain as substring (e.g., official-domain-secure.com)
    2. Extra hyphens with keywords (e.g., official-domain-pay.com)
    3. Common keyword additions: pay, secure, app, login, account, verify
    
    Args:
        domain: Scanned domain to check
        official_domain: Known official domain
    
    Returns:
        List of detected suspicious patterns
    """
    patterns = []
    
    # Check if official domain is contained in the scanned domain
    # (but they're not exactly equal)
    if official_domain in domain and domain != official_domain:
        patterns.append(f"Contains official domain '{official_domain}' as substring")
    
    # Extract the base domain without TLD for pattern matching
    # Example: "official-domain.com" → "official-domain"
    scanned_base = domain.rsplit(".", 1)[0] if "." in domain else domain
    official_base = official_domain.rsplit(".", 1)[0] if "." in official_domain else official_domain
    
    # Check for suspicious keyword suffixes
    suspicious_keywords = [
        "pay", "payment", "secure", "security", "app", "login", 
        "account", "verify", "auth", "wallet", "charge", "charging"
    ]
    
    for keyword in suspicious_keywords:
        if scanned_base.endswith(f"-{keyword}") and official_base in scanned_base:
            patterns.append(f"Suspicious keyword suffix '-{keyword}' added to official domain")
    
    return patterns


def check_typosquatting(
    scanned_domain: str, 
    official_domains: List[str],
    distance_threshold: int = 2
) -> Tuple[bool, Optional[str], List[str]]:
    """
    Check if a scanned domain is a typosquatting attempt.
    
    Combines Levenshtein distance and pattern matching to detect:
    - Character-level similarity (distance <= threshold)
    - Suspicious domain patterns (keyword additions, substrings)
    
    Security Rationale:
    A distance threshold of 2 catches most common typos and substitutions
    while minimizing false positives. Pattern matching catches more
    sophisticated attacks like domain-keyword.com.
    
    Args:
        scanned_domain: Domain from the QR code
        official_domains: List of legitimate company domains
        distance_threshold: Maximum Levenshtein distance to consider suspicious
    
    Returns:
        Tuple of (is_suspicious, closest_match, reasons)
        - is_suspicious: True if typosquatting detected
        - closest_match: The official domain that's most similar (if any)
        - reasons: List of specific findings
    
    Example:
        >>> check_typosquatting(
        ...     "officia1-domain.com", 
        ...     ["official-domain.com"],
        ...     distance_threshold=2
        ... )
        (True, "official-domain.com", ["Levenshtein distance 1 from 'official-domain.com'"])
    """
    scanned_lower = scanned_domain.lower().strip()
    reasons = []
    closest_match = None
    min_distance = float('inf')
    
    for official_domain in official_domains:
        official_lower = official_domain.lower().strip()
        
        # Skip if domains are identical (exact match is handled elsewhere)
        if scanned_lower == official_lower:
            continue
        
        # Calculate edit distance
        distance = calculate_levenshtein_distance(scanned_lower, official_lower)
        
        # Track the closest official domain
        if distance < min_distance:
            min_distance = distance
            closest_match = official_domain
        
        # Check if distance is suspiciously low
        if distance <= distance_threshold:
            reasons.append(
                f"Levenshtein distance {distance} from official domain '{official_domain}' "
                f"(threshold: {distance_threshold})"
            )
        
        # Check for pattern-based attacks
        patterns = detect_suspicious_patterns(scanned_lower, official_lower)
        reasons.extend(patterns)
    
    is_suspicious = len(reasons) > 0
    
    return is_suspicious, closest_match, reasons
