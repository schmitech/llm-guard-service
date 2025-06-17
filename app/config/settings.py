from pydantic_settings import BaseSettings
from typing import List, Optional

class Settings(BaseSettings):
    # Service configuration
    service_name: str = "llm-guard-service"
    service_version: str = "1.0.0"
    service_port: int = 8001
    
    # Redis configuration
    redis_url: str = "redis://localhost:6379"
    cache_ttl: int = 3600
    
    # Security configuration
    default_risk_threshold: float = 0.6
    enable_caching: bool = True
    
    # Scanner configuration
    enabled_input_scanners: List[str] = [
        "anonymize",
        "ban_substrings", 
        "ban_topics",
        "code",
        "prompt_injection",
        "secrets",
        "toxicity"
    ]
    
    enabled_output_scanners: List[str] = [
        "bias",
        "no_refusal",
        "relevance",
        "sensitive"
    ]
    
    # Logging
    log_level: str = "INFO"
    
    class Config:
        env_file = ".env"

settings = Settings()