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
import os
from logging.handlers import TimedRotatingFileHandler
import logging.config
import yaml

# Global services
guard_service: Optional[LLMGuardService] = None
cache_service: Optional[CacheService] = None

# Ensure logs directory exists
logs_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs'))
os.makedirs(logs_dir, exist_ok=True)

# Try to load logging config from config.yaml  
# __file__ is app/main.py, so we need to go up two levels to get to the project root
config_path = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.yaml'))
if os.path.exists(config_path):
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        if 'logging' in config:
            logging.config.dictConfig(config['logging'])
            print(f"Loaded logging config from: {config_path}")
        else:
            print("No logging config found in config.yaml, using basic config")
            logging.basicConfig(level=logging.INFO)
    except Exception as e:
        print(f"Failed to load logging config from config.yaml: {e}")
        logging.basicConfig(level=logging.INFO)
else:
    print(f"Config file not found at: {config_path}")
    logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)
logger.info("Logger initialized successfully")

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