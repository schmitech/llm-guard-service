from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum

class ContentType(str, Enum):
    PROMPT = "prompt"
    OUTPUT = "output"

class SecurityCheckRequest(BaseModel):
    content: str = Field(..., description="Content to check")
    content_type: ContentType = Field(..., description="Type of content")
    scanners: Optional[List[str]] = Field(None, description="Specific scanners to use")
    risk_threshold: Optional[float] = Field(0.6, ge=0.0, le=1.0)
    user_id: Optional[str] = Field(None, description="User identifier for logging")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

class SecurityCheckResponse(BaseModel):
    is_safe: bool
    risk_score: float = Field(..., ge=0.0, le=1.0)
    sanitized_content: str
    flagged_scanners: List[str] = Field(default_factory=list)
    scanner_results: Dict[str, Any] = Field(default_factory=dict)
    recommendations: List[str] = Field(default_factory=list)
    processing_time_ms: float

class SanitizeRequest(BaseModel):
    content: str
    sanitizers: Optional[List[str]] = None
    
class HealthResponse(BaseModel):
    status: str
    version: str
    scanners_loaded: int
    cache_connected: bool