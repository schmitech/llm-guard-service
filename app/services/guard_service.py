import time
import hashlib
import json
import logging
import os
import sys
import contextlib
from typing import List, Dict, Any, Optional, Tuple
from llm_guard.input_scanners import (
    Anonymize, BanSubstrings, BanTopics, Code,
    PromptInjection, Secrets, Toxicity
)
from llm_guard.vault import Vault
from llm_guard.output_scanners import (
    Bias, NoRefusal, Relevance, Sensitive
)
from app.config.settings import settings
from app.models.request_models import ContentType, SecurityCheckResponse
from app.services.cache_service import CacheService

logger = logging.getLogger(__name__)

class LLMGuardService:
    def __init__(self):
        self.input_scanners = {}
        self.output_scanners = {}
        self.cache_service = CacheService() if settings.enable_caching else None
        self._configure_presidio()
        self._initialize_scanners()
    
    def _configure_presidio(self):
        """Configure presidio analyzer settings"""
        if settings.presidio_config:
            presidio_config = settings.presidio_config
            
            # Create a presidio configuration file
            try:
                import json
                presidio_config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'presidio_config.json')
                
                # Create configuration dict for presidio
                presidio_file_config = {}
                
                if "model_to_presidio_entity_mapping" in presidio_config:
                    presidio_file_config["model_to_presidio_entity_mapping"] = presidio_config["model_to_presidio_entity_mapping"]
                
                if "low_score_entity_names" in presidio_config:
                    presidio_file_config["low_score_entity_names"] = presidio_config["low_score_entity_names"]
                
                if "labels_to_ignore" in presidio_config:
                    presidio_file_config["labels_to_ignore"] = presidio_config["labels_to_ignore"]
                
                if "supported_languages" in presidio_config:
                    presidio_file_config["supported_languages"] = presidio_config["supported_languages"]
                
                # Write configuration file
                with open(presidio_config_path, 'w') as f:
                    json.dump(presidio_file_config, f, indent=2)
                
                # Set environment variable to point to config file
                os.environ["PRESIDIO_ANALYZER_CONFIG"] = presidio_config_path
                
                logger.info(f"Created presidio configuration file at: {presidio_config_path}")
                
            except Exception as e:
                logger.warning(f"Could not create presidio configuration file: {e}")
        
    @contextlib.contextmanager
    def _suppress_debug_output(self):
        """Context manager to suppress debug output during model loading"""
        # Check if verbose initialization is enabled
        verbose_init = settings.llm_guard_service_config.get('verbose_initialization', False)
        if verbose_init:
            # Don't suppress output if verbose initialization is enabled
            yield
            return
            
        # Save original stderr and stdout
        original_stderr = sys.stderr
        original_stdout = sys.stdout
        
        try:
            # Redirect to devnull to suppress debug messages
            with open(os.devnull, 'w') as devnull:
                sys.stderr = devnull
                sys.stdout = devnull
                yield
        finally:
            # Restore original stderr and stdout
            sys.stderr = original_stderr
            sys.stdout = original_stdout

    def _initialize_scanners(self):
        """Initialize all configured scanners"""
        logger.info("Initializing scanners...")
        
        # Get security scanner configurations
        security_config = settings.llm_guard_service_config.get('security_scanners', {})
        
        # Input scanners
        if "anonymize" in settings.enabled_input_scanners:
            # Presidio configuration is handled via environment variables in _configure_presidio
            with self._suppress_debug_output():
                self.input_scanners["anonymize"] = Anonymize(vault=Vault())
            
        if "ban_substrings" in settings.enabled_input_scanners:
            # Get configuration from settings - no hardcoded fallbacks
            ban_substrings_config = security_config.get('ban_substrings', {})
            if not ban_substrings_config.get('enabled', False):
                logger.warning("ban_substrings scanner is in enabled list but not properly configured in security_scanners section")
            else:
                substrings = ban_substrings_config.get('substrings', [])
                if not substrings:
                    logger.error("ban_substrings: No substrings configured - scanner will not be effective")
                    
                case_sensitive = ban_substrings_config.get('case_sensitive', False)
                
                with self._suppress_debug_output():
                    self.input_scanners["ban_substrings"] = BanSubstrings(
                        substrings=substrings,
                        case_sensitive=case_sensitive
                    )
                
        if "ban_topics" in settings.enabled_input_scanners:
            # Get configuration from settings - no hardcoded fallbacks
            ban_topics_config = security_config.get('ban_topics', {})
            if not ban_topics_config.get('enabled', False):
                logger.warning("ban_topics scanner is in enabled list but not properly configured in security_scanners section")
            else:
                topics = ban_topics_config.get('topics', [])
                if not topics:
                    logger.error("ban_topics: No topics configured - scanner will not be effective")
                    
                threshold = ban_topics_config.get('threshold')
                if threshold is None:
                    logger.error("ban_topics: No threshold configured - scanner cannot function")
                else:
                    with self._suppress_debug_output():
                        self.input_scanners["ban_topics"] = BanTopics(
                            topics=topics,
                            threshold=threshold
                        )
                
        if "code" in settings.enabled_input_scanners:
            # Get configuration from settings for code scanner languages
            code_config = security_config.get('code', {})
            languages = code_config.get('languages', ["Python", "JavaScript"])  # Default maintained for backward compatibility
            
            with self._suppress_debug_output():
                self.input_scanners["code"] = Code(languages=languages)
                
        if "prompt_injection" in settings.enabled_input_scanners:
            # Get configuration from settings - no hardcoded fallbacks
            prompt_injection_config = security_config.get('prompt_injection', {})
            if not prompt_injection_config.get('enabled', False):
                logger.warning("prompt_injection scanner is in enabled list but not properly configured in security_scanners section")
            else:
                threshold = prompt_injection_config.get('threshold')
                if threshold is None:
                    logger.error("prompt_injection: No threshold configured - using default behavior")
                    with self._suppress_debug_output():
                        self.input_scanners["prompt_injection"] = PromptInjection()
                else:
                    with self._suppress_debug_output():
                        if threshold < 1.0:
                            self.input_scanners["prompt_injection"] = PromptInjection(threshold=threshold)
                        else:
                            self.input_scanners["prompt_injection"] = PromptInjection()
                
        if "secrets" in settings.enabled_input_scanners:
            # Enhanced secrets scanner configuration
            secrets_config = security_config.get('secrets', {})
            redact_token = secrets_config.get('redact_token', '[REDACTED]')
            allowed_secrets = secrets_config.get('allowed_secrets', [])
            
            with self._suppress_debug_output():
                if redact_token != '[REDACTED]' or allowed_secrets:
                    # Use enhanced configuration
                    self.input_scanners["secrets"] = Secrets(
                        redact_token=redact_token,
                        allowed_secrets=allowed_secrets
                    )
                else:
                    # Use default configuration
                    self.input_scanners["secrets"] = Secrets()
                
        if "toxicity" in settings.enabled_input_scanners:
            # Get configuration from settings - no hardcoded fallbacks  
            toxicity_config = security_config.get('toxicity', {})
            if not toxicity_config.get('enabled', False):
                logger.warning("toxicity scanner is in enabled list but not properly configured in security_scanners section")
            else:
                threshold = toxicity_config.get('threshold')
                if threshold is None:
                    logger.error("toxicity: No threshold configured - using default behavior")
                    with self._suppress_debug_output():
                        self.input_scanners["toxicity"] = Toxicity()
                else:
                    with self._suppress_debug_output():
                        if threshold < 1.0:
                            self.input_scanners["toxicity"] = Toxicity(threshold=threshold)
                        else:
                            self.input_scanners["toxicity"] = Toxicity()
        
        # Output scanners
        if "bias" in settings.enabled_output_scanners:
            with self._suppress_debug_output():
                self.output_scanners["bias"] = Bias()
                
        if "no_refusal" in settings.enabled_output_scanners:
            with self._suppress_debug_output():
                self.output_scanners["no_refusal"] = NoRefusal()
                
        if "relevance" in settings.enabled_output_scanners:
            with self._suppress_debug_output():
                self.output_scanners["relevance"] = Relevance()
                
        if "sensitive" in settings.enabled_output_scanners:
            with self._suppress_debug_output():
                self.output_scanners["sensitive"] = Sensitive()
            
        logger.info(f"Initialized {len(self.input_scanners)} input scanners and {len(self.output_scanners)} output scanners")
    
    async def check_content(
        self, 
        content: str, 
        content_type: ContentType,
        scanners: Optional[List[str]] = None,
        risk_threshold: float = 0.6,
        user_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        original_prompt: Optional[str] = None  # Added for output scanning with Relevance
    ) -> SecurityCheckResponse:
        """Main security check method with fail-safe error handling"""
        start_time = time.time()
        
        # Check cache first
        cache_key = self._generate_cache_key(content, content_type, scanners, original_prompt)
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
        
        # Run scans with fail-safe mechanism
        scanner_results = {}
        flagged_scanners = []
        sanitized_content = content
        risk_scores = []
        scanner_failed = False
        
        for scanner_name, scanner in active_scanners.items():
            try:
                # Pass original_prompt for relevance scanner in output scanning
                if scanner_name == "relevance" and content_type == ContentType.OUTPUT and original_prompt:
                    result = self._run_scanner_with_prompt(scanner, sanitized_content, original_prompt)
                else:
                    result = self._run_scanner(scanner, sanitized_content)
                
                # Check for critical scanner errors
                if "error" in result:
                    logger.error(f"Critical scanner failure for {scanner_name}: {result['error']}")
                    scanner_failed = True
                    break  # Immediate fail-safe exit
                    
                scanner_results[scanner_name] = result
                
                if not result.get("is_valid", True):
                    flagged_scanners.append(scanner_name)
                    risk_scores.append(result.get("risk_score", 1.0))
                    
                # Update sanitized content if scanner provides it
                if "sanitized_prompt" in result:
                    sanitized_content = result["sanitized_prompt"]
                    
            except Exception as e:
                logger.error(f"Critical error running scanner {scanner_name}: {e}")
                scanner_failed = True
                break  # Immediate fail-safe exit
        
        # Fail-safe response if any scanner failed
        if scanner_failed:
            processing_time_ms = (time.time() - start_time) * 1000
            return SecurityCheckResponse(
                is_safe=False,
                risk_score=1.0,
                sanitized_content=content,  # Return original content when failing safe
                flagged_scanners=["system_error"],
                scanner_results={"system_error": {"error": "Scanner system failure - content marked unsafe as precaution"}},
                recommendations=["System security check failed. Please try again or contact support if the issue persists."],
                processing_time_ms=processing_time_ms
            )
        
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
        
        # Enhanced caching logic with strict safety controls
        cache_config = settings.llm_guard_service_config.get('cache', {})
        should_cache = False
        cache_ttl = settings.cache_ttl  # Default fallback
        
        if self.cache_service:
            # Enforce cache_only_safe: true as a security requirement
            cache_only_safe = cache_config.get('cache_only_safe', True)
            if not cache_only_safe:
                logger.warning("cache_only_safe is disabled - this poses a security risk")
            
            if is_safe and cache_only_safe:
                # Cache safe results with configurable TTL
                cache_ttl = cache_config.get('safe_result_ttl', settings.cache_ttl)
                should_cache = cache_ttl > 0
            elif not is_safe and not cache_only_safe:
                # Cache unsafe results only if explicitly enabled (not recommended)
                cache_ttl = cache_config.get('unsafe_result_ttl', 0)
                should_cache = cache_ttl > 0
                if should_cache:
                    logger.warning("Caching unsafe result - this may pose security risks")
            
            if should_cache:
                await self.cache_service.set(
                    cache_key, 
                    response.model_dump_json(),
                    ttl=cache_ttl
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
    
    def _run_scanner_with_prompt(self, scanner: Any, content: str, original_prompt: str) -> Dict[str, Any]:
        """Run a scanner that requires the original prompt (like Relevance for output scanning)"""
        try:
            scanner_type = type(scanner).__name__
            
            if scanner_type == "Relevance" and hasattr(scanner, 'scan'):
                # Relevance scanner needs the original prompt to compare against output
                prompt, is_valid, risk_score = scanner.scan(original_prompt, content)
                return {
                    "is_valid": is_valid,
                    "risk_score": risk_score,
                    "sanitized_prompt": prompt
                }
            elif hasattr(scanner, 'scan'):
                # Fallback to regular scan method
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
            logger.error(f"Scanner with prompt execution failed: {e}")
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
        scanners: Optional[List[str]],
        original_prompt: Optional[str] = None
    ) -> str:
        """Generate cache key for content with configuration versioning"""
        # Include scanner configuration in cache key for auto-invalidation
        scanner_config_hash = self._get_scanner_config_hash()
        
        key_parts = [
            content,
            content_type.value,
            ",".join(sorted(scanners)) if scanners else "all",
            scanner_config_hash,  # This makes cache invalid when config changes
            original_prompt if content_type == ContentType.OUTPUT and original_prompt else ""
        ]
        key_string = "|".join(key_parts)
        return f"security:{hashlib.sha256(key_string.encode()).hexdigest()}"
    
    def _get_scanner_config_hash(self) -> str:
        """Generate hash of current scanner configuration for cache versioning"""
        import json
        
        # Get all relevant configuration that affects scanning
        config_data = {
            "enabled_input_scanners": settings.enabled_input_scanners,
            "enabled_output_scanners": settings.enabled_output_scanners,
            "default_risk_threshold": settings.default_risk_threshold,
            "scanner_configs": settings.llm_guard_service_config.get('security_scanners', {})
        }
        
        # Create a deterministic hash of the configuration
        config_json = json.dumps(config_data, sort_keys=True)
        return hashlib.sha256(config_json.encode()).hexdigest()[:8]  # Use first 8 chars
    
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
            
        if "ban_substrings" in flagged_scanners:
            recommendations.append("Banned keywords or phrases detected. Please modify your request to avoid prohibited terms.")
            
        if "ban_topics" in flagged_scanners:
            recommendations.append("Content relates to prohibited topics. Please ensure your request is for legitimate purposes only.")
            
        return recommendations