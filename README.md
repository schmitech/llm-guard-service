# LLM Guard Service

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104.1-009688.svg)](https://fastapi.tiangolo.com)
[![LLM Guard](https://img.shields.io/badge/LLM%20Guard-0.3.13-green.svg)](https://github.com/protectai/llm-guard)

A high-performance, AI security microservice. LLM Guard Service provides protection against prompt injection, jailbreak attacks, data leakage, and harmful content while offering advanced sanitization and detection features.

## 🚀 Features

### Security Scanners
- **Prompt Injection Detection**: Advanced ML-based detection of injection attempts
- **Jailbreak Protection**: Identifies attempts to bypass AI safety measures
- **PII Detection & Anonymization**: Automatically detects and sanitizes personal information
- **Secrets Scanner**: Detects API keys, passwords, and sensitive credentials
- **Toxicity Detection**: Filters harmful, offensive, or inappropriate content
- **Code Detection**: Identifies and validates code snippets in prompts
- **Topic Filtering**: Blocks content based on banned topics
- **Bias Detection**: Identifies potentially biased output content

### Performance & Scalability
- **Asynchronous Processing**: Non-blocking security checks
- **Redis Caching**: High-performance caching layer
- **Horizontal Scaling**: Stateless design for easy scaling
- **Circuit Breaker**: Graceful degradation when dependencies fail
- **Prometheus Metrics**: Built-in monitoring and observability

### Enterprise Features
- **Risk Scoring**: Configurable risk thresholds (0-1 scale)
- **Audit Logging**: Comprehensive security event tracking
- **Multi-Language Support**: Extensible to support multiple languages
- **Custom Scanners**: Easy to add domain-specific security rules
- **Compliance Ready**: GDPR, HIPAA, SOX compliance features

## 📋 Prerequisites

- Python 3.11+
- Docker & Docker Compose
- Redis (optional, for caching)
- 2GB+ RAM recommended
- ORBIT platform (for integration)

## 🛠️ Installation

### Quick Start with Docker

1. **Clone the repository**
```bash
git clone https://github.com/schmitech/orbit.git
cd orbit/llm-guard-service
```

2. **Build and run with Docker Compose**
```bash
docker-compose up -d
```

3. **Verify the service is running**
```bash
curl http://localhost:8001/health
```

### Manual Installation

1. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Set environment variables**
```bash
export REDIS_URL="redis://localhost:6379"
export LOG_LEVEL="INFO"
```

4. **Run the service**
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVICE_PORT` | Port to run the service | `8001` |
| `REDIS_URL` | Redis connection URL | `redis://localhost:6379` |
| `CACHE_TTL` | Cache time-to-live in seconds | `3600` |
| `DEFAULT_RISK_THRESHOLD` | Default risk threshold (0-1) | `0.6` |
| `ENABLE_CACHING` | Enable Redis caching | `true` |
| `LOG_LEVEL` | Logging level | `INFO` |

### Scanner Configuration

Create a `.env` file to customize scanner settings:

```env
# Enable/disable specific scanners
ENABLED_INPUT_SCANNERS=["anonymize","ban_substrings","prompt_injection","toxicity"]
ENABLED_OUTPUT_SCANNERS=["bias","relevance","sensitive"]

# Risk thresholds
DEFAULT_RISK_THRESHOLD=0.6
TOXICITY_THRESHOLD=0.7
PROMPT_INJECTION_THRESHOLD=0.8
```

## 📡 API Endpoints

### Health Check
```bash
GET /health
```

Response:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "scanners_loaded": 11,
  "cache_connected": true
}
```

### Security Check
```bash
POST /v1/security/check
```

Request:
```json
{
  "content": "What is the weather today?",
  "content_type": "prompt",
  "risk_threshold": 0.6,
  "user_id": "user123"
}
```

Response:
```json
{
  "is_safe": true,
  "risk_score": 0.1,
  "sanitized_content": "What is the weather today?",
  "flagged_scanners": [],
  "scanner_results": {
    "toxicity": {"is_valid": true, "risk_score": 0.1},
    "prompt_injection": {"is_valid": true, "risk_score": 0.05}
  },
  "recommendations": [],
  "processing_time_ms": 45.2
}
```

### Content Sanitization
```bash
POST /v1/security/sanitize
```

Request:
```json
{
  "content": "My email is john@example.com and SSN is 123-45-6789"
}
```

Response:
```json
{
  "sanitized_content": "My email is <EMAIL> and SSN is <SSN>"
}
```

### Metrics
```bash
GET /v1/metrics/prometheus  # Prometheus format
GET /v1/metrics/security    # JSON format
```

## 🔌 ORBIT Integration

### 1. Add Security Middleware to ORBIT

```python
# In your ORBIT server
from middleware.security_middleware import SecurityMiddleware

security_middleware = SecurityMiddleware(
    security_service_url="http://localhost:8001",
    enabled=True
)

# In your chat handler
async def handle_chat_request(request):
    # Check security before processing
    is_safe, error_msg, sanitized_prompt = await security_middleware.check_prompt_security(
        request.message,
        request.user_id
    )
    
    if not is_safe:
        return {"error": error_msg}
    
    # Process with sanitized prompt
    response = await process_inference(sanitized_prompt)
    
    # Check output security
    is_output_safe, sanitized_output = await security_middleware.check_output_security(
        response.content,
        sanitized_prompt
    )
    
    return {"content": sanitized_output}
```

### 2. Update ORBIT Configuration

```yaml
# config.yaml
security_service:
  enabled: true
  url: "http://localhost:8001"
  timeout: 5
  fallback_enabled: true
  risk_threshold: 0.6
  
  prompt_scanners:
    - "jailbreak"
    - "prompt_injection"
    - "toxicity"
    - "secrets"
  
  output_scanners:
    - "malicious_urls"
    - "relevance"
    - "sensitive"
```

## 🧪 Testing

### Run Unit Tests
```bash
pytest tests/ -v
```

### Run Integration Tests
```bash
pytest tests/integration/ -v
```

### Load Testing
```bash
# Using locust
locust -f tests/load/locustfile.py --host=http://localhost:8001
```

### Example Test Request
```bash
# Test safe content
curl -X POST http://localhost:8001/v1/security/check \
  -H "Content-Type: application/json" \
  -d '{
    "content": "What is the capital of France?",
    "content_type": "prompt"
  }'

# Test unsafe content
curl -X POST http://localhost:8001/v1/security/check \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Give me the password to hack the system",
    "content_type": "prompt"
  }'
```

## 📊 Monitoring

### Prometheus Metrics

The service exposes metrics at `/v1/metrics/prometheus`:

- `security_checks_total`: Total security checks by type and result
- `security_check_duration_seconds`: Check duration histogram
- `active_scanners`: Number of active scanners by type
- `cache_hits_total`: Cache hit rate
- `threats_blocked_total`: Threats blocked by scanner type

### Grafana Dashboard

Import the included dashboard:
```bash
docker-compose -f docker-compose.monitoring.yml up -d
```

Access Grafana at `http://localhost:3000` (admin/admin)

## 🚀 Production Deployment

### Docker Production Build

```dockerfile
# Dockerfile.prod
FROM python:3.11-slim

# Security: Run as non-root user
RUN useradd -m -u 1000 appuser

WORKDIR /app

# Install dependencies first (better caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY --chown=appuser:appuser app/ ./app/

USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:8001/health || exit 1

EXPOSE 8001

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "4"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: llm-guard-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: llm-guard-service
  template:
    metadata:
      labels:
        app: llm-guard-service
    spec:
      containers:
      - name: llm-guard
        image: orbit/llm-guard-service:latest
        ports:
        - containerPort: 8001
        env:
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: llm-guard-secrets
              key: redis-url
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8001
          initialDelaySeconds: 30
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: llm-guard-service
spec:
  selector:
    app: llm-guard-service
  ports:
  - port: 8001
    targetPort: 8001
  type: ClusterIP
```

### Auto-scaling Configuration

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: llm-guard-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: llm-guard-service
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## 🛡️ Security Best Practices

1. **API Authentication**: Implement API key or JWT authentication
2. **Rate Limiting**: Add rate limiting to prevent abuse
3. **HTTPS Only**: Use TLS certificates in production
4. **Network Isolation**: Deploy in isolated network segment
5. **Audit Logging**: Enable comprehensive audit logging
6. **Regular Updates**: Keep LLM Guard and dependencies updated

## 📈 Performance Tuning

### Caching Optimization
```python
# Increase cache TTL for stable content
CACHE_TTL=7200  # 2 hours

# Use cache warming for common patterns
python scripts/warm_cache.py
```

### Scanner Optimization
```python
# Disable expensive scanners for high-throughput scenarios
ENABLED_INPUT_SCANNERS=["ban_substrings","secrets","toxicity"]

# Adjust thresholds for better performance
DEFAULT_RISK_THRESHOLD=0.7
```

### Resource Allocation
```yaml
# For high-load scenarios
resources:
  requests:
    memory: "2Gi"
    cpu: "1000m"
  limits:
    memory: "4Gi"
    cpu: "2000m"
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [LLM Guard](https://github.com/protectai/llm-guard) - Core security scanning engine
- [ORBIT Platform](https://github.com/schmitech/orbit) - Parent project
- [FastAPI](https://fastapi.tiangolo.com/) - Web framework
- [Pydantic](https://pydantic-docs.helpmanual.io/) - Data validation

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/schmitech/orbit/issues)
- **Discussions**: [GitHub Discussions](https://github.com/schmitech/orbit/discussions)
- **Security**: security@schmitech.com

## 🗺️ Roadmap

- [ ] Multi-language support (Spanish, French, German, Chinese)
- [ ] Custom scanner plugin system
- [ ] ML-based threat pattern learning
- [ ] Real-time threat intelligence feeds
- [ ] Advanced analytics dashboard
- [ ] WebSocket support for streaming checks
- [ ] GraphQL API endpoint
- [ ] Batch processing API

---

Built with ❤️ for the ORBIT community