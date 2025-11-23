"""
QR Güvenlik Servisi - Main FastAPI Application

Production-ready backend for QR code security analysis in EV charging scenarios.

This service protects users from QR code-based attacks including:
- QR sticker replacement (fake QR codes on charging stations)
- Phishing attacks via malicious websites
- Malware distribution (APK sideloading, EXE downloads)
- Credential theft and session hijacking

Security Features:
- HTTPS enforcement
- Domain allowlist/denylist
- Typosquatting detection
- Malicious file detection
- Redirect risk assessment
- Comprehensive audit logging

Author: Generated for EV Charging Security Project
"""

from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# New imports for v1 API
from app.core.config import settings
from app.db.session import init_db
from app.api.v1.endpoints import analyze

# Legacy imports (keep for backward compatibility)
from app.config import get_settings as get_legacy_settings
from app.routers import anomaly, domains, qr, stations

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format=settings.LOG_FORMAT
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    
    Handles startup and shutdown events:
    - Startup: Initialize database tables
    - Shutdown: Cleanup resources (if needed)
    """
    # Startup
    logger.info("Initializing database...")
    await init_db()
    logger.info("[OK] Database tables initialized")
    logger.info(f"[OK] {settings.APP_NAME} v{settings.APP_VERSION} started successfully")
    print(f"[INFO] API Documentation: http://localhost:8000/docs")
    
    yield
    
    # Shutdown
    print(f"[BYE] {settings.APP_NAME} shutting down")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    description="""
    **QR Güvenlik Servisi** - EV Charging QR Code Security Analysis API
    
    This service analyzes QR codes scanned at EV charging stations and determines
    their security risk level before the mobile app opens them.
    
    ## Security Checks Performed
    
    1. **HTTPS Enforcement** - Ensures encrypted connections
    2. **Domain Verification** - Validates against official domain allowlist
    3. **Typosquatting Detection** - Identifies fake domains similar to official ones
    4. **Malicious File Detection** - Flags dangerous downloads (APK, EXE, etc.)
    5. **Redirect Analysis** - Detects open redirect vulnerabilities
    
    ## Risk Scoring
    
    - **0-39 (Safe)**: Low risk, legitimate content
    - **40-79 (Suspicious)**: Potential security concerns, user should be cautious
    - **80-100 (Malicious)**: High confidence threat, should be blocked
    
    ## Use Cases
    
    - Mobile app scans QR code → sends to this API → receives verdict
    - Security monitoring and audit logging
    - Station-specific attack pattern analysis
    - Domain reputation management
    """,
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS (adjust for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Restrict to specific origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount frontend directory for static assets
app.mount("/static", StaticFiles(directory="frontend"), name="static")
app.mount("/css", StaticFiles(directory="frontend/css"), name="css")
app.mount("/js", StaticFiles(directory="frontend/js"), name="js")

# Include NEW v1 API routers
app.include_router(analyze.router, prefix="/api/v1/analyze", tags=["Analysis v1"])

# Legacy routers (backward compatibility)
app.include_router(qr.router)
app.include_router(stations.router)
app.include_router(domains.router)
app.include_router(anomaly.router)


@app.get(
    "/",
    tags=["Frontend"],
    summary="Serve Frontend",
    description="Serves the main frontend application."
)
async def root():
    """Serve the frontend index.html"""
    return FileResponse('frontend/index.html')


@app.get(
    "/api/health",
    tags=["Health"],
    summary="Health Check",
    description="Health check endpoint for monitoring and load balancers."
)
async def health():
    """
    Health check endpoint.
    
    Returns:
        Status information about the service
    """
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "version": "1.0.0"
    }


# Development server entry point
if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
