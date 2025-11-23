"""
Configuration management for QR Security Service.
Uses Pydantic settings for environment-based configuration.
"""

from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    Environment variables can be defined in:
    - .env file (for local development)
    - System environment (for production)
    - Docker Compose environment section
    """
    
    # Application metadata
    app_name: str = "QR Security Service"
    app_version: str = "1.0.0"
    
    # Database configuration
    # Example: postgresql+asyncpg://postgres:postgres@db:5432/qr_security
    database_url: str
    
    # Security configuration - official domains for QR code validation
    # Comma-separated list of trusted domains
    # Example: "official-domain.com,charge.official-domain.com,app.official-domain.com"
    official_domains: str = "official-domain.com"
    
    # Logging
    log_level: str = "INFO"
    
    # CORS settings (configure for production)
    cors_origins: str = "*"  # Change to specific origins in production
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )
    
    @property
    def official_domains_list(self) -> List[str]:
        """
        Parse the comma-separated official domains into a list.
        Strips whitespace and filters empty strings.
        
        Returns:
            List of official domain strings in lowercase
        """
        return [
            domain.strip().lower() 
            for domain in self.official_domains.split(",") 
            if domain.strip()
        ]


# Global settings instance
settings = Settings()
