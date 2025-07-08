# Deployment Guide

This guide covers everything you need to know about deploying the HTTP Keep-Alive Analyzer in different environments, from development to production.

## Table of Contents

- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Deployment Options](#deployment-options)
- [Production Considerations](#production-considerations)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

## Quick Start

### Prerequisites

Choose one of these options:

**Option A: Go Development Environment**
- Go 1.21 or later
- Basic familiarity with command line

**Option B: Docker Environment**
- Docker installed and running
- Basic familiarity with Docker commands

### 5-Minute Setup

**With Go:**
```bash
# Clone and build
git clone <repository-url>
cd http-keepalive
go build -o http-keepalive main.go

# Run with defaults
./http-keepalive
```

**With Docker:**
```bash
# Build and run
docker build -t http-keepalive .
docker run -p 3000:3000 http-keepalive
```

Visit `http://localhost:3000` to use the web interface.

## Configuration

### Environment Variables

The application uses environment variables for configuration. Here's what each setting controls:

#### Server Configuration

```bash
# Port the HTTP server listens on
PORT=3000

# Directory containing web assets (HTML, CSS, JS)
PUBLIC_DIR=./public

# HTTP server timeouts
SERVER_READ_TIMEOUT=30s     # How long to wait for request headers
SERVER_WRITE_TIMEOUT=30s    # How long to wait to write responses
SERVER_IDLE_TIMEOUT=120s    # How long to keep connections open
```

**When to change these:**
- Change `PORT` if 3000 conflicts with other services
- Change `PUBLIC_DIR` if you're serving static files from a different location
- Increase timeouts if you're analyzing very slow websites

#### DNS Configuration

```bash
# Which DNS server to use for lookups
DNS_SERVER=8.8.8.8          # Google's public DNS
# DNS_SERVER=1.1.1.1        # Cloudflare's DNS (alternative)
# DNS_SERVER=system          # Use system DNS resolver

# How long to wait for DNS responses
DNS_TIMEOUT=5s

# Whether to use the system's DNS cache
DNS_USE_CACHED=false
```

**When to change these:**
- Use `DNS_SERVER=system` if you're behind a corporate firewall
- Increase `DNS_TIMEOUT` if you're analyzing domains with slow DNS
- Set `DNS_USE_CACHED=true` for faster repeated lookups of the same domains

#### HTTP Analysis Configuration

```bash
# How long to wait for HTTP responses
HTTP_TIMEOUT=30s

# User agent string sent with requests
HTTP_USER_AGENT="HTTP Keep-Alive Analyzer/2.0"

# Maximum number of redirects to follow
HTTP_MAX_REDIRECTS=5

# Whether to verify SSL certificates
HTTP_INSECURE_SKIP_VERIFY=false
```

**When to change these:**
- Increase `HTTP_TIMEOUT` for very slow websites
- Change `HTTP_USER_AGENT` if websites are blocking the default string
- Set `HTTP_INSECURE_SKIP_VERIFY=true` only for testing with self-signed certificates

#### TCP Analysis Configuration

```bash
# How long to wait for TCP connections
TCP_TIMEOUT=10s

# How many times to retry failed connections
TCP_MAX_RETRIES=3

# Delay between retry attempts
TCP_RETRY_DELAY=1s

# Buffer size for reading TCP data
TCP_BUFFER_SIZE=4096
```

**When to change these:**
- Increase timeouts and retries for unreliable networks
- Reduce timeouts for faster analysis of responsive sites

#### CSP Analysis Configuration

```bash
# How long to wait when fetching pages for CSP analysis
CSP_TIMEOUT=30s

# User agent for CSP analysis requests
CSP_USER_AGENT="HTTP Keep-Alive Analyzer CSP/2.0"

# How deep to analyze linked resources
CSP_MAX_DEPTH=3

# Whether to follow redirects during CSP analysis
CSP_FOLLOW_REDIRECTS=true
```

**When to change these:**
- Reduce `CSP_MAX_DEPTH` for faster analysis
- Set `CSP_FOLLOW_REDIRECTS=false` if you only want to analyze the exact URL provided

### Configuration Files

You can also use configuration files instead of environment variables:

**config.yaml:**
```yaml
server:
  port: ":3000"
  public_dir: "./public"
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "120s"

dns:
  server: "8.8.8.8"
  timeout: "5s"
  use_cached: false

http:
  timeout: "30s"
  user_agent: "HTTP Keep-Alive Analyzer/2.0"
  max_redirects: 5
  insecure_skip_verify: false

tcp:
  timeout: "10s"
  max_retries: 3
  retry_delay: "1s"
  buffer_size: 4096

csp:
  timeout: "30s"
  user_agent: "HTTP Keep-Alive Analyzer CSP/2.0"
  max_depth: 3
  follow_redirects: true
```

**config.json:**
```json
{
  "server": {
    "port": ":3000",
    "public_dir": "./public",
    "read_timeout": "30s",
    "write_timeout": "30s",
    "idle_timeout": "120s"
  },
  "dns": {
    "server": "8.8.8.8",
    "timeout": "5s",
    "use_cached": false
  },
  "http": {
    "timeout": "30s",
    "user_agent": "HTTP Keep-Alive Analyzer/2.0",
    "max_redirects": 5,
    "insecure_skip_verify": false
  },
  "tcp": {
    "timeout": "10s",
    "max_retries": 3,
    "retry_delay": "1s",
    "buffer_size": 4096
  },
  "csp": {
    "timeout": "30s",
    "user_agent": "HTTP Keep-Alive Analyzer CSP/2.0",
    "max_depth": 3,
    "follow_redirects": true
  }
}
```

## Deployment Options

### Development Deployment

For local development and testing:

```bash
# Clone the repository
git clone <repository-url>
cd http-keepalive

# Install dependencies
go mod download

# Run in development mode (with live reloading)
go run main.go

# Or build and run
go build -o http-keepalive main.go
./http-keepalive
```

**Development features:**
- Detailed error messages
- Hot reloading (if using `go run`)
- Debug logging enabled

### Docker Deployment

#### Basic Docker Setup

```bash
# Build the image
docker build -t http-keepalive .

# Run the container
docker run -d \
  --name http-keepalive \
  -p 3000:3000 \
  --restart unless-stopped \
  http-keepalive
```

#### Docker with Custom Configuration

```bash
# Run with environment variables
docker run -d \
  --name http-keepalive \
  -p 3000:3000 \
  -e PORT=3000 \
  -e DNS_SERVER=1.1.1.1 \
  -e HTTP_TIMEOUT=60s \
  --restart unless-stopped \
  http-keepalive
```

#### Docker Compose

**docker-compose.yml:**
```yaml
version: '3.8'

services:
  http-keepalive:
    build: .
    ports:
      - "3000:3000"
    environment:
      - PORT=3000
      - DNS_SERVER=8.8.8.8
      - HTTP_TIMEOUT=30s
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

Run with:
```bash
docker-compose up -d
```

### Cloud Deployment

#### AWS (Elastic Beanstalk)

1. **Create Dockerfile** (already provided)

2. **Create .ebextensions/app.config:**
```yaml
option_settings:
  aws:elasticbeanstalk:application:environment:
    PORT: 3000
    DNS_SERVER: 8.8.8.8
```

3. **Deploy:**
```bash
eb init
eb create production
eb deploy
```

#### Google Cloud Platform (Cloud Run)

1. **Build and push image:**
```bash
gcloud builds submit --tag gcr.io/PROJECT-ID/http-keepalive
```

2. **Deploy:**
```bash
gcloud run deploy --image gcr.io/PROJECT-ID/http-keepalive --platform managed
```

#### Azure (Container Instances)

```bash
az container create \
  --resource-group myResourceGroup \
  --name http-keepalive \
  --image myregistry.azurecr.io/http-keepalive:latest \
  --dns-name-label http-keepalive \
  --ports 3000
```

#### DigitalOcean (App Platform)

**app.yaml:**
```yaml
name: http-keepalive
services:
- name: web
  source_dir: /
  github:
    repo: your-username/http-keepalive
    branch: main
  run_command: ./http-keepalive
  environment_slug: docker
  instance_count: 1
  instance_size_slug: basic-xxs
  envs:
  - key: PORT
    value: "3000"
  http_port: 3000
```

### Kubernetes Deployment

#### Basic Deployment

**k8s-deployment.yaml:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: http-keepalive
spec:
  replicas: 2
  selector:
    matchLabels:
      app: http-keepalive
  template:
    metadata:
      labels:
        app: http-keepalive
    spec:
      containers:
      - name: http-keepalive
        image: http-keepalive:latest
        ports:
        - containerPort: 3000
        env:
        - name: PORT
          value: "3000"
        - name: DNS_SERVER
          value: "8.8.8.8"
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "128Mi"
            cpu: "200m"
        livenessProbe:
          httpGet:
            path: /api/health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/health
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: http-keepalive-service
spec:
  selector:
    app: http-keepalive
  ports:
  - protocol: TCP
    port: 80
    targetPort: 3000
  type: LoadBalancer
```

Apply with:
```bash
kubectl apply -f k8s-deployment.yaml
```

## Production Considerations

### Security

#### Network Security

```bash
# Run on non-privileged port
PORT=8080

# Bind to specific interface
BIND_ADDRESS=127.0.0.1:8080  # Only local access
# BIND_ADDRESS=0.0.0.0:8080  # All interfaces
```

#### Reverse Proxy Setup

**Nginx Configuration:**
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/m;
    
    location /api/ {
        limit_req zone=api burst=5 nodelay;
        proxy_pass http://localhost:3000;
        # ... same proxy settings as above
    }
}
```

**Apache Configuration:**
```apache
<VirtualHost *:80>
    ServerName your-domain.com
    
    ProxyPreserveHost On
    ProxyPass / http://localhost:3000/
    ProxyPassReverse / http://localhost:3000/
    
    # Rate limiting (requires mod_evasive)
    DOSHashTableSize 4096
    DOSPageCount 3
    DOSPageInterval 1
    DOSSiteCount 50
    DOSSiteInterval 1
</VirtualHost>
```

### Performance Optimization

#### Resource Limits

```bash
# Limit memory usage
GOMEMLIMIT=512MiB

# Limit concurrent requests
HTTP_MAX_CONCURRENT_REQUESTS=100

# Optimize garbage collection
GOGC=100
```

#### Caching

For high-traffic deployments, consider adding a cache layer:

**Redis Integration (if implemented):**
```bash
REDIS_URL=redis://localhost:6379
CACHE_TTL=300s  # 5 minutes
```

### Logging and Monitoring

#### Structured Logging

```bash
# JSON logging for production
LOG_FORMAT=json

# Log level
LOG_LEVEL=info  # debug, info, warn, error

# Log file location
LOG_FILE=/var/log/http-keepalive/app.log
```

#### Health Checks

The application provides a health check endpoint at `/api/health`:

```bash
# Basic health check
curl http://localhost:3000/api/health

# Detailed health check (if implemented)
curl http://localhost:3000/api/health?detailed=true
```

#### Metrics (if implemented)

```bash
# Prometheus metrics endpoint
curl http://localhost:3000/metrics

# Custom metrics configuration
METRICS_ENABLED=true
METRICS_PORT=9090
```

### Backup and Recovery

#### Configuration Backup

```bash
# Backup configuration
tar -czf config-backup-$(date +%Y%m%d).tar.gz \
  config.yaml \
  .env \
  docker-compose.yml

# Backup logs
tar -czf logs-backup-$(date +%Y%m%d).tar.gz /var/log/http-keepalive/
```

#### Disaster Recovery

```bash
# Quick restoration
docker pull http-keepalive:latest
docker run -d --name http-keepalive-backup \
  -p 3001:3000 \
  --env-file .env.backup \
  http-keepalive:latest
```

## Monitoring

### Application Metrics

Monitor these key metrics:

**Request Metrics:**
- Request rate (requests per second)
- Response time percentiles (p50, p90, p99)
- Error rate by endpoint
- Success rate by analysis type

**Resource Metrics:**
- Memory usage
- CPU usage
- Network connections
- Disk I/O

**Business Metrics:**
- Domains analyzed per hour
- Most frequently analyzed domains
- Analysis success rate by domain type

### Log Analysis

Key log patterns to monitor:

```bash
# Error patterns
grep "ERROR" /var/log/http-keepalive/app.log

# Slow requests (>5 seconds)
grep "duration.*[5-9][0-9][0-9][0-9]ms" /var/log/http-keepalive/app.log

# Failed DNS resolutions
grep "DNS resolution failed" /var/log/http-keepalive/app.log

# Connection timeouts
grep "timeout" /var/log/http-keepalive/app.log
```

### Alerting

Set up alerts for:

**Critical Issues:**
- Application down (health check failing)
- High error rate (>5% over 5 minutes)
- Memory usage >90%
- Disk space <10%

**Warning Issues:**
- High response time (>2s average over 5 minutes)
- DNS resolution failures >10% over 5 minutes
- CPU usage >80% over 10 minutes

## Troubleshooting

### Common Issues

#### Application Won't Start

**Problem:** Port already in use
```
Error: listen tcp :3000: bind: address already in use
```

**Solution:**
```bash
# Find what's using the port
lsof -i :3000

# Use a different port
PORT=3001 ./http-keepalive

# Or kill the conflicting process
kill $(lsof -t -i:3000)
```

**Problem:** Permission denied
```
Error: listen tcp :80: bind: permission denied
```

**Solution:**
```bash
# Use a non-privileged port
PORT=8080 ./http-keepalive

# Or run with proper permissions (not recommended)
sudo ./http-keepalive
```

#### DNS Resolution Issues

**Problem:** Can't resolve any domains
```
DNS resolution failed for all domains
```

**Solution:**
```bash
# Test DNS manually
nslookup google.com 8.8.8.8

# Try different DNS server
DNS_SERVER=1.1.1.1 ./http-keepalive

# Use system DNS
DNS_SERVER=system ./http-keepalive
```

#### Connection Timeouts

**Problem:** All requests timing out
```
HTTP analysis failed: context deadline exceeded
```

**Solution:**
```bash
# Increase timeouts
HTTP_TIMEOUT=60s ./http-keepalive

# Check network connectivity
curl -I http://google.com

# Check firewall rules
```

#### High Memory Usage

**Problem:** Application consuming too much memory

**Solution:**
```bash
# Limit memory
GOMEMLIMIT=256MiB ./http-keepalive

# Reduce concurrent analysis
HTTP_MAX_CONCURRENT_REQUESTS=10 ./http-keepalive

# Monitor with htop or similar
htop -p $(pgrep http-keepalive)
```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
# Enable debug logs
LOG_LEVEL=debug ./http-keepalive

# Enable all debug features
DEBUG=true LOG_LEVEL=debug ./http-keepalive
```

### Getting Help

1. **Check the logs** for specific error messages
2. **Test with a simple domain** like `google.com`
3. **Verify network connectivity** to the target domain
4. **Check configuration** for typos or invalid values
5. **Review resource usage** (memory, CPU, disk)

If issues persist:
- Check the project's issue tracker
- Provide logs and configuration when reporting problems
- Include steps to reproduce the issue

### Performance Tuning

#### For High-Traffic Scenarios

```bash
# Increase connection limits
HTTP_MAX_CONCURRENT_REQUESTS=200

# Optimize timeouts
HTTP_TIMEOUT=15s
TCP_TIMEOUT=5s
DNS_TIMEOUT=3s

# Reduce analysis depth
CSP_MAX_DEPTH=1
```

#### For Accuracy Over Speed

```bash
# Increase timeouts
HTTP_TIMEOUT=60s
TCP_TIMEOUT=30s
DNS_TIMEOUT=10s

# More retries
TCP_MAX_RETRIES=5

# Deeper analysis
CSP_MAX_DEPTH=5
```

This deployment guide should help you get the HTTP Keep-Alive Analyzer running smoothly in any environment. Remember to start with the basic setup and gradually add complexity as needed for your specific use case.