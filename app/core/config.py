"""
Core configuration using Pydantic Settings.
Handles all environment variables and application settings.
"""
from typing import List, Optional
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
    # Application Info
    APP_NAME: str = "QR Security Analyzer"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False
    
    # Security
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./chargesentinel.db"
    
    # QR Security Settings
    OFFICIAL_DOMAIN: str = "https://official-charging-domain.com"
    
    # Trusted third-party domains that should NOT be flagged as high-risk
    # These are well-known, legitimate sites that may appear in QR codes
    TRUSTED_THIRD_PARTIES: List[str] = [
        # Google services
        "google.com",
        "www.google.com",
        "play.google.com",
        "maps.google.com",
        "accounts.google.com",
        "developers.google.com",
        
        # Apple services
        "apple.com",
        "www.apple.com",
        "apps.apple.com",
        
        # Common legitimate services
        "github.com",
        "stackoverflow.com",
        "wikipedia.org",
        "youtube.com",
        
        # Payment providers (add your trusted payment gateways)
        "stripe.com",
        "paypal.com",
        
        # Add more trusted domains as needed
    ]
    
    # Risk Scoring Thresholds
    RISK_THRESHOLD_LOW: int = 30      # 0-30 = low risk
    RISK_THRESHOLD_MEDIUM: int = 60   # 31-60 = medium risk
                                       # 61-100 = high risk
    
    # URL Inspection Settings
    URL_FETCH_TIMEOUT: int = 10  # seconds
    URL_FETCH_MAX_SIZE: int = 5 * 1024 * 1024  # 5MB max
    URL_FOLLOW_REDIRECTS: bool = True
    URL_MAX_REDIRECTS: int = 5
    
    # QR Image Settings
    QR_MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB max
    QR_ALLOWED_FORMATS: List[str] = ["png", "jpg", "jpeg", "gif", "bmp"]
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8000"]
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )
    
    @field_validator("TRUSTED_THIRD_PARTIES", mode="before")
    @classmethod
    def parse_trusted_domains(cls, v):
        """Parse trusted domains from environment variable if string."""
        if isinstance(v, str):
            return [domain.strip() for domain in v.split(",")]
        return v
    
    def is_official_domain(self, url: str) -> bool:
        """Check if URL belongs to official domain."""
        return self.OFFICIAL_DOMAIN.lower() in url.lower()
    
    def is_trusted_third_party(self, domain: str) -> bool:
        """Check if domain is in trusted third-party list."""
        domain_lower = domain.lower().replace("www.", "")
        for trusted in self.TRUSTED_THIRD_PARTIES:
            trusted_clean = trusted.lower().replace("www.", "")
            if domain_lower == trusted_clean or domain_lower.endswith(f".{trusted_clean}"):
                return True
        return False
    
    def get_risk_level(self, score: int) -> str:
        """Convert numeric risk score to risk level."""
        if score <= self.RISK_THRESHOLD_LOW:
            return "low"
        elif score <= self.RISK_THRESHOLD_MEDIUM:
            return "medium"
        else:
            return "high"


# Global settings instance
settings = Settings()
