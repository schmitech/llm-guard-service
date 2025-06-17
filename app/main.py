from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager
from typing import Optional
import logging
from app.config.settings import settings
from app.services.guard_service import LLMGuardService
from app.services.cache_service import CacheService
from app.models.request_models import (
    SecurityCheckRequest, SecurityCheckResponse,
    SanitizeRequest, HealthResponse
)
from app.routers import metrics

# Configure logging
logging.basicConfig(level=settings.log_level)
logger = logging.getLogger(__name__)

# Global services
guard_service: Optional[LLMGuardService] = None
cache_service: Optional[CacheService] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle"""
    global guard_service, cache_service
    
    # Startup
    logger.info("Starting LLM Guard Service...")
    
    # Initialize services
    guard_service = LLMGuardService()
    
    if settings.enable_caching:
        cache_service = guard_service.cache_service
        if cache_service:
            await cache_service.connect()
    
    logger.info("LLM Guard Service started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down LLM Guard Service...")
    
    if cache_service:
        await cache_service.disconnect()
        
    logger.info("LLM Guard Service shutdown complete")

# Create FastAPI app
app = FastAPI(
    title="ORBIT LLM Guard Service",
    description="AI Security and Moderation Service for ORBIT",
    version=settings.service_version,
    lifespan=lifespan
)

# Include routers
app.include_router(metrics.router, prefix="/v1/metrics", tags=["metrics"])

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    if not guard_service:
        raise HTTPException(status_code=503, detail="Service not initialized")
    return HealthResponse(
        status="healthy",
        version=settings.service_version,
        scanners_loaded=len(guard_service.input_scanners) + len(guard_service.output_scanners),
        cache_connected=cache_service.connected if cache_service else False
    )

@app.post("/v1/security/check", response_model=SecurityCheckResponse)
async def check_security(request: SecurityCheckRequest):
    """
    Perform comprehensive security check on content
    """
    if not guard_service:
        raise HTTPException(status_code=503, detail="Service not initialized")
    try:
        result = await guard_service.check_content(
            content=request.content,
            content_type=request.content_type,
            scanners=request.scanners,
            risk_threshold=request.risk_threshold or 0.5,
            user_id=request.user_id,
            metadata=request.metadata
        )
        return result
    except Exception as e:
        logger.error(f"Security check failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/v1/security/sanitize")
async def sanitize_content(request: SanitizeRequest):
    """
    Sanitize content while preserving functionality
    """
    if not guard_service:
        raise HTTPException(status_code=503, detail="Service not initialized")
    try:
        # Use anonymize scanner for sanitization
        anonymizer = guard_service.input_scanners.get("anonymize")
        if not anonymizer:
            raise HTTPException(status_code=501, detail="Sanitization not available")
            
        sanitized, _, _ = anonymizer.scan(request.content)
        return {"sanitized_content": sanitized}
    except Exception as e:
        logger.error(f"Sanitization failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))