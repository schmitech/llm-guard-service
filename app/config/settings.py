from pydantic_settings import BaseSettings
from typing import List, Optional, Dict, Any
import yaml
import os

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
    
    # Presidio configuration - loaded from config.yaml
    presidio_config: Optional[Dict[str, Any]] = None
    
    # LLM Guard service configuration
    llm_guard_service_config: Optional[Dict[str, Any]] = None
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._load_presidio_config()
    
    def _load_presidio_config(self):
        """Load presidio configuration from config.yaml"""
        try:
            config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'config.yaml')
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f)
                    self.presidio_config = config.get('presidio', {})
                    self.llm_guard_service_config = config.get('llm_guard_service', {})
        except Exception as e:
            # Silently fall back to empty config if loading fails
            self.presidio_config = {}
            self.llm_guard_service_config = {}
    
    class Config:
        env_file = ".env.local"  # Changed to use .env.local
        env_file_encoding = "utf-8"

settings = Settings()