"""
ML Model Training Script.

This script trains a Random Forest classifier to detect phishing URLs.
It uses a synthetic dataset for demonstration purposes.

Steps:
1. Define dataset (Safe vs Phishing URLs)
2. Extract features using the same logic as the main app
3. Train model
4. Save model to .pkl file
"""

import os
import sys
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# Add project root to path to import app modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.services.qr_analyzer_ml import extract_url_features

# ==========================================
# 1. DATASET (Synthetic)
# ==========================================
# In a real project, load this from a large CSV file.
OFFICIAL_DOMAINS = ["official-domain.com", "charge.official-domain.com"]

SAFE_URLS = [
    "https://official-domain.com/charge/cp001",
    "https://official-domain.com/login",
    "https://charge.official-domain.com/start",
    "https://app.official-domain.com/download",
    "https://google.com",
    "https://apple.com",
    "https://microsoft.com",
    "https://github.com",
    "https://stackoverflow.com",
    "https://www.amazon.com",
    "https://en.wikipedia.org/wiki/QR_code",
    "https://official-domain.com/support",
    "https://official-domain.com/contact",
    "https://maps.google.com",
    "https://charge-network.com/stations",
]

PHISHING_URLS = [
    "http://officlal-domain.com/login",  # Typosquatting
    "http://official-domain-secure.com/update",
    "http://192.168.1.5/malware.apk",    # IP address
    "http://free-charging-bonus.com/claim",
    "http://secure-payment-gateway-update.com",
    "http://official-domain.com.verify-account.xyz/login", # Subdomain trick
    "http://bit.ly/fake-promo",
    "http://tinyurl.com/malicious",
    "http://update-your-car.com/firmware.exe",
    "http://charge-bonus.net/login.php",
    "http://official-domian.com",        # Typosquatting
    "http://go0gle.com/drive",
    "http://pay-pal-secure.com",
    "http://apple-id-verify.com",
    "http://microsoft-support-urgent.com"
]

def main():
    print("[INFO] Training ML Model for URL Phishing Detection...")
    print("-" * 50)
    
    # Prepare data
    X = []
    y = []
    
    print(f"Processing {len(SAFE_URLS)} safe URLs...")
    for url in SAFE_URLS:
        features = extract_url_features(url, OFFICIAL_DOMAINS)
        X.append(features[0])
        y.append(0) # 0 = Safe
        
    print(f"Processing {len(PHISHING_URLS)} phishing URLs...")
    for url in PHISHING_URLS:
        features = extract_url_features(url, OFFICIAL_DOMAINS)
        X.append(features[0])
        y.append(1) # 1 = Phishing
        
    X = np.array(X)
    y = np.array(y)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train model
    print("\nTraining Random Forest Classifier...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    
    # Evaluate
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n[SUCCESS] Model Accuracy: {acc * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))
    
    # Save model
    os.makedirs("models", exist_ok=True)
    model_path = "models/url_phishing_model.pkl"
    joblib.dump(clf, model_path)
    
    print("-" * 50)
    print(f"[DONE] Model saved to: {model_path}")
    print("Ready for inference!")

if __name__ == "__main__":
    main()
