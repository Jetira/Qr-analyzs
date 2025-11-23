"""
QR Security Service - FastAPI Application

Production-ready backend for analyzing QR codes in EV charging stations.
Detects phishing attacks, malicious redirects, and fake QR sticker replacements.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import create_tables
from app.routers import qr
from app.logging_utils import setup_logging
from app.schemas import HealthResponse

# Configure logging
setup_logging(settings.log_level)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan context manager.
    
    Handles startup and shutdown events:
    - Startup: Create database tables
    - Shutdown: Cleanup resources (if needed)
    """
    # Startup
    logger.info("Starting QR Security Service...")
    logger.info(f"Official domains: {settings.official_domains_list}")
    
    try:
        await create_tables()
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down QR Security Service...")


# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="""
    **QR Security Service** - Phishing Detection for EV Charging Stations
    
    ## Purpose
    Analyzes QR codes before they are opened by mobile apps to prevent:
    - Phishing attacks via fake QR stickers
    - Malicious APK downloads (sideloading)
    - Credential theft through typosquatted domains
    - Session hijacking via insecure connections
    
    ## Security Rules
    This service implements five security checks:
    1. **HTTPS Enforcement** - Reject HTTP connections
    2. **Domain Allowlist** - Verify official company domains
    3. **Typosquatting Detection** - Catch similar-looking domains
    4. **Malicious Files** - Block APK/EXE downloads
    5. **Redirect Detection** - Flag dynamic redirect parameters
    
    ## Workflow
    1. Mobile app scans QR code
    2. App sends QR data to `/analyze-qr` endpoint
    3. Backend analyzes and returns verdict
    4. App decides: open URL, show warning, or block
    
    ## Documentation
    - Interactive API docs: `/docs`
    - Alternative docs: `/redoc`
    """,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


# ============================================================================
# CORS Middleware
# ============================================================================

# Configure CORS for mobile app requests
# In production, replace "*" with specific mobile app origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(",") if settings.cors_origins != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Include Routers
# ============================================================================

app.include_router(
    qr.router,
    tags=["QR Analysis"]
)


# ============================================================================
# Root Endpoint
# ============================================================================

@app.get("/", response_model=dict)
async def root():
    """
    Root endpoint with API information.
    
    Returns:
        API metadata and links to documentation
    """
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "status": "operational",
        "docs": "/docs",
        "health": "/health",
        "description": "QR Security Service for EV Charging Stations",
        "endpoints": {
            "analyze": "POST /analyze-qr",
            "scan_history": "GET /stations/{station_code}/scans",
            "domains": "GET /domains, POST /domains",
        }
    }


# ============================================================================
# Health Check Endpoint
# ============================================================================

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint for monitoring.
    
    Use this endpoint for:
    - Docker health checks
    - Load balancer health probes
    - Uptime monitoring tools
    
    Returns:
        HealthResponse with service status
    """
    return HealthResponse(
        status="ok",
        app=settings.app_name,
        version=settings.app_version
    )


# ============================================================================
# Error Handlers (Optional: Add custom error handling here)
# ============================================================================

# Example: Custom 404 handler
# @app.exception_handler(404)
# async def not_found_handler(request, exc):
#     return JSONResponse(
#         status_code=404,
#         content={"detail": "Resource not found"}
#     )


if __name__ == "__main__":
    import uvicorn
    
    # Development server
    # In production, use: uvicorn app.main:app --host 0.0.0.0 --port 8000
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,  # Enable auto-reload for development
        log_level=settings.log_level.lower()
    )
