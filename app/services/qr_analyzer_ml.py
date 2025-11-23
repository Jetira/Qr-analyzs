"""
URL Phishing Classifier (Supervised ML).

This module provides functionality to:
1. Extract numerical features from URLs.
2. Load a pre-trained scikit-learn model.
3. Predict phishing probability for a given URL.

The model is assumed to be trained offline and saved as a .pkl file.
"""

import os
import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import joblib
import numpy as np
from sklearn.base import BaseEstimator

from app.logging_utils import log_error
from app.security.typosquatting import levenshtein_distance


def extract_url_features(url: str, official_domains: List[str]) -> np.ndarray:
    """
    Build a numeric feature vector from the given URL.
    
    Features extracted:
    1. Total length of URL
    2. Length of hostname
    3. Number of dots in host
    4. Number of digits in host
    5. Path length
    6. Number of path segments
    7. Presence of suspicious keywords (1/0)
    8. Ratio of digits to total characters in host
    9. Minimum Levenshtein distance to official domains
    10. Is IP address (1/0)
    
    Args:
        url: The URL to analyze
        official_domains: List of official domains for distance comparison
        
    Returns:
        Numpy array of shape (1, n_features)
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        
        # 1. Total length
        url_len = len(url)
        
        # 2. Hostname length
        host_len = len(host)
        
        # 3. Dots in host
        dot_count = host.count('.')
        
        # 4. Digits in host
        digit_count = sum(c.isdigit() for c in host)
        
        # 5. Path length
        path_len = len(path)
        
        # 6. Path segments
        path_segments = len([s for s in path.split('/') if s])
        
        # 7. Suspicious keywords
        keywords = ['login', 'verify', 'secure', 'bank', 'pay', 'otp', 'update', 'confirm', 'account']
        full_text = (host + path + query).lower()
        has_keyword = 1 if any(kw in full_text for kw in keywords) else 0
        
        # 8. Digit ratio in host
        digit_ratio = digit_count / host_len if host_len > 0 else 0.0
        
        # 9. Min distance to official domains
        min_dist = 100  # Default high value
        if official_domains and host:
            distances = [levenshtein_distance(host, d) for d in official_domains]
            min_dist = min(distances) if distances else 100
            
        # 10. Is IP address
        is_ip = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host) else 0
        
        # Create feature vector
        features = np.array([
            url_len,
            host_len,
            dot_count,
            digit_count,
            path_len,
            path_segments,
            has_keyword,
            digit_ratio,
            min_dist,
            is_ip
        ]).reshape(1, -1)
        
        return features
        
    except Exception as e:
        log_error("Feature extraction failed", e)
        # Return zero vector on error to prevent crash
        return np.zeros((1, 10))


def load_url_model(path: str) -> Optional[BaseEstimator]:
    """
    Load a scikit-learn model via joblib from the given path.
    
    Args:
        path: Path to the .pkl model file
        
    Returns:
        Loaded model or None if loading fails
    """
    if not os.path.exists(path):
        return None
        
    try:
        model = joblib.load(path)
        return model
    except Exception as e:
        log_error(f"Failed to load ML model from {path}", e)
        return None


def ml_score_url(
    url: str,
    official_domains: List[str],
    model: Optional[BaseEstimator]
) -> Tuple[Optional[float], Optional[str]]:
    """
    Predict phishing probability using the ML model.
    
    Args:
        url: URL to analyze
        official_domains: List of official domains
        model: Loaded scikit-learn model
        
    Returns:
        Tuple of (probability, reason_string)
        Probability is 0.0-1.0 (or None if failed)
    """
    if model is None:
        return None, None
        
    try:
        # Extract features
        features = extract_url_features(url, official_domains)
        
        # Predict probability (class 1 = phishing)
        # Check if model supports predict_proba
        if hasattr(model, "predict_proba"):
            prob = model.predict_proba(features)[0][1]
        else:
            # Fallback for models without probability (e.g. SVM without probability=True)
            pred = model.predict(features)[0]
            prob = 1.0 if pred == 1 else 0.0
            
        reason = None
        if prob >= 0.5:
            percentage = int(prob * 100)
            reason = f"ML model predicted phishing probability at ~{percentage}%"
            
        return prob, reason
        
    except Exception as e:
        log_error("ML inference failed", e)
        return None, None
