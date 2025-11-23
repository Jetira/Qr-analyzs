"""
Configuration management for QR Güvenlik Servisi.

This module uses Pydantic Settings to load configuration from environment variables.
Settings are cached using lru_cache to avoid re-parsing on every request.
"""

from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    Environment variables:
    - DATABASE_URL: PostgreSQL async connection string (asyncpg driver)
    - OFFICIAL_DOMAINS: Comma-separated list of trusted domains
    - APP_NAME: Application name for metadata
    - LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR)
    """
    
    # Database configuration
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/qr_security"
    
    # Application metadata
    APP_NAME: str = "QR Güvenlik Servisi"
    LOG_LEVEL: str = "INFO"
    
    # Security configuration
    # Official domains that are considered safe for QR codes
    # Example: "official-domain.com,charge.official-domain.com,app.official-domain.com"
    OFFICIAL_DOMAINS: str = ""

    # Machine Learning Configuration
    ML_URL_MODEL_PATH: str = "models/url_phishing_model.pkl"
    ML_URL_ENABLED: bool = True
    
    # Notification Configuration
    SLACK_WEBHOOK_URL: str = ""  # Empty string means disabled
    
    class Config:
        """Pydantic configuration."""
        env_file = ".env"
        env_file_encoding = "utf-8"
    
    @property
    def official_domains_list(self) -> List[str]:
        """
        Parse OFFICIAL_DOMAINS into a list of domain strings.
        
        Returns:
            List of official domain strings (lowercased and stripped).
        """
        if not self.OFFICIAL_DOMAINS:
            return []
        return [
            domain.strip().lower()
            for domain in self.OFFICIAL_DOMAINS.split(",")
            if domain.strip()
        ]


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    This function is cached to avoid re-parsing environment variables
    on every request. Can be used as a FastAPI dependency.
    
    Returns:
        Settings instance with all configuration loaded.
    """
    return Settings()
