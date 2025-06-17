import time
import hashlib
import json
from typing import List, Dict, Any, Optional, Tuple
from llm_guard.input_scanners import (
    Anonymize, BanSubstrings, BanTopics, Code,
    PromptInjection, Secrets, Toxicity
)
from llm_guard.output_scanners import (
    Bias, NoRefusal, Relevance, Sensitive
)
from app.config.settings import settings
from app.models.request_models import ContentType, SecurityCheckResponse
from app.services.cache_service import CacheService
import logging

logger = logging.getLogger(__name__)

class LLMGuardService:
    def __init__(self):
        self.input_scanners = {}
        self.output_scanners = {}
        self.cache_service = CacheService() if settings.enable_caching else None
        self._initialize_scanners()
        
    def _initialize_scanners(self):
        """Initialize all configured scanners"""
        # Input scanners
        if "anonymize" in settings.enabled_input_scanners:
            self.input_scanners["anonymize"] = Anonymize()
            
        if "ban_substrings" in settings.enabled_input_scanners:
            self.input_scanners["ban_substrings"] = BanSubstrings(
                substrings=["password", "api_key", "secret", "token"],
                case_sensitive=False
            )
            
        if "ban_topics" in settings.enabled_input_scanners:
            self.input_scanners["ban_topics"] = BanTopics(
                topics=["violence", "illegal", "hate"]
            )
            
        if "code" in settings.enabled_input_scanners:
            self.input_scanners["code"] = Code(languages=["python", "javascript"])
            
        if "prompt_injection" in settings.enabled_input_scanners:
            self.input_scanners["prompt_injection"] = PromptInjection()
            
        if "secrets" in settings.enabled_input_scanners:
            self.input_scanners["secrets"] = Secrets()
            
        if "toxicity" in settings.enabled_input_scanners:
            self.input_scanners["toxicity"] = Toxicity()
        
        # Output scanners
        if "bias" in settings.enabled_output_scanners:
            self.output_scanners["bias"] = Bias()
            
        if "no_refusal" in settings.enabled_output_scanners:
            self.output_scanners["no_refusal"] = NoRefusal()
            
        if "relevance" in settings.enabled_output_scanners:
            self.output_scanners["relevance"] = Relevance()
            
        if "sensitive" in settings.enabled_output_scanners:
            self.output_scanners["sensitive"] = Sensitive()
            
        logger.info(f"Initialized {len(self.input_scanners)} input scanners and {len(self.output_scanners)} output scanners")
    
    async def check_content(
        self, 
        content: str, 
        content_type: ContentType,
        scanners: Optional[List[str]] = None,
        risk_threshold: float = 0.6,
        user_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SecurityCheckResponse:
        """Main security check method"""
        start_time = time.time()
        
        # Check cache first
        cache_key = self._generate_cache_key(content, content_type, scanners)
        if self.cache_service:
            cached_result = await self.cache_service.get(cache_key)
            if cached_result:
                logger.info(f"Cache hit for content check")
                return SecurityCheckResponse(**json.loads(cached_result))
        
        # Select appropriate scanners
        if content_type == ContentType.PROMPT:
            active_scanners = self._get_active_scanners(self.input_scanners, scanners)
        else:
            active_scanners = self._get_active_scanners(self.output_scanners, scanners)
        
        # Run scans
        scanner_results = {}
        flagged_scanners = []
        sanitized_content = content
        risk_scores = []
        
        for scanner_name, scanner in active_scanners.items():
            try:
                result = self._run_scanner(scanner, sanitized_content)
                scanner_results[scanner_name] = result
                
                if not result.get("is_valid", True):
                    flagged_scanners.append(scanner_name)
                    risk_scores.append(result.get("risk_score", 1.0))
                    
                # Update sanitized content if scanner provides it
                if "sanitized_prompt" in result:
                    sanitized_content = result["sanitized_prompt"]
                    
            except Exception as e:
                logger.error(f"Error running scanner {scanner_name}: {e}")
                scanner_results[scanner_name] = {"error": str(e)}
        
        # Calculate overall risk score
        risk_score = max(risk_scores) if risk_scores else 0.0
        is_safe = risk_score < risk_threshold
        
        # Generate recommendations
        recommendations = self._generate_recommendations(flagged_scanners, scanner_results)
        
        # Create response
        processing_time_ms = (time.time() - start_time) * 1000
        response = SecurityCheckResponse(
            is_safe=is_safe,
            risk_score=risk_score,
            sanitized_content=sanitized_content,
            flagged_scanners=flagged_scanners,
            scanner_results=scanner_results,
            recommendations=recommendations,
            processing_time_ms=processing_time_ms
        )
        
        # Cache result
        if self.cache_service and is_safe:
            await self.cache_service.set(
                cache_key, 
                response.model_dump_json(),
                ttl=settings.cache_ttl
            )
        
        # Log security event
        logger.info(
            f"Security check completed - "
            f"safe: {is_safe}, risk: {risk_score:.2f}, "
            f"flagged: {flagged_scanners}, time: {processing_time_ms:.2f}ms"
        )
        
        return response
    
    def _run_scanner(self, scanner: Any, content: str) -> Dict[str, Any]:
        """Run a single scanner and return results"""
        try:
            # Different scanners have different interfaces
            scanner_type = type(scanner).__name__
            
            if hasattr(scanner, 'scan'):
                prompt, is_valid, risk_score = scanner.scan(content)
                return {
                    "is_valid": is_valid,
                    "risk_score": risk_score,
                    "sanitized_prompt": prompt
                }
            else:
                # Fallback for scanners with different interfaces
                result = scanner(content)
                return {"result": result, "is_valid": True, "risk_score": 0.0}
                
        except Exception as e:
            logger.error(f"Scanner execution failed: {e}")
            return {"error": str(e), "is_valid": False, "risk_score": 1.0}
    
    def _get_active_scanners(
        self, 
        scanner_dict: Dict[str, Any], 
        requested_scanners: Optional[List[str]]
    ) -> Dict[str, Any]:
        """Get the scanners to use for this check"""
        if requested_scanners:
            return {k: v for k, v in scanner_dict.items() if k in requested_scanners}
        return scanner_dict
    
    def _generate_cache_key(
        self, 
        content: str, 
        content_type: ContentType,
        scanners: Optional[List[str]]
    ) -> str:
        """Generate cache key for content"""
        key_parts = [
            content,
            content_type.value,
            ",".join(sorted(scanners)) if scanners else "all"
        ]
        key_string = "|".join(key_parts)
        return f"security:{hashlib.sha256(key_string.encode()).hexdigest()}"
    
    def _generate_recommendations(
        self, 
        flagged_scanners: List[str], 
        scanner_results: Dict[str, Any]
    ) -> List[str]:
        """Generate recommendations based on scan results"""
        recommendations = []
        
        if "prompt_injection" in flagged_scanners:
            recommendations.append("Potential prompt injection detected. Review and sanitize user input.")
            
        if "secrets" in flagged_scanners:
            recommendations.append("Sensitive data detected. Remove API keys or secrets from content.")
            
        if "toxicity" in flagged_scanners:
            recommendations.append("Toxic content detected. Please rephrase in a constructive manner.")
            
        if "code" in flagged_scanners:
            recommendations.append("Code detected in input. Ensure code execution is intended.")
            
        return recommendations