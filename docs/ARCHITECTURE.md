# Architecture Documentation

This document explains the internal architecture of the HTTP Keep-Alive Analyzer, how the components work together, and key design decisions.

## Overview

The HTTP Keep-Alive Analyzer follows a modular, layered architecture that separates concerns and makes the codebase maintainable and extensible. The application is built with Go and follows idiomatic Go patterns.

## High-Level Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                    Web Interface (React-style JS)           │
│                    ├── HTML/CSS/JavaScript                  │
│                    └── API Documentation Tab                │
└─────────────────────────────────────────────────────────────┘
                                │
                                │ HTTP/JSON
                                ▼
┌─────────────────────────────────────────────────────────────┐
│                    HTTP Handlers Layer                      │
│    ├── Web Interface Handler (/)                           │
│    ├── Analysis Handler (/analyze)                         │
│    ├── API Endpoints (/api/analyze, /api/health)          │
│    └── Static File Server (/public/)                       │
└─────────────────────────────────────────────────────────────┘
                                │
                                │ Service Calls
                                ▼
┌─────────────────────────────────────────────────────────────┐
│                    Analysis Service Layer                   │
│    └── Orchestrates all analysis components                │
└─────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────┼───────────┐
                    │           │           │
                    ▼           ▼           ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│     DNS     │ │    HTTP     │ │     TCP     │ │     CSP     │
│  Resolver   │ │  Analyzer   │ │  Analyzer   │ │ Evaluator   │
│             │ │             │ │             │ │             │
│ ├─System    │ │ ├─Headers   │ │ ├─Handshake │ │ ├─Policy    │
│ ├─Google    │ │ ├─Keep-Alive│ │ ├─Flags     │ │ ├─Security  │
│ └─Caching   │ │ ├─CDN       │ │ └─Timing    │ │ └─Compliance│
│             │ │ ├─Server ID │ │             │ │             │
│             │ │ └─TLS       │ │             │ │             │
└─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘
```

## Core Components

### 1. Main Entry Point (`main.go`)

**Purpose**: Application bootstrap and dependency injection.

**Key responsibilities:**
- Load configuration from environment variables and files
- Initialize all service dependencies with proper configuration
- Set up HTTP server with routes and middleware
- Handle graceful shutdown with signal handling

**Design patterns used:**
- Dependency Injection: All services receive their dependencies explicitly
- Configuration Object: Centralized configuration management
- Graceful Shutdown: Proper cleanup on termination signals

```go
// Example of dependency initialization
func initializeDependencies(cfg *config.Config) (*handlers.Dependencies, *dns.Config) {
    // Each service gets its own configuration
    dnsConfig := &dns.Config{
        UseCachedDNS: cfg.DNS.UseCachedDNS,
        DNSServer:    cfg.DNS.DefaultServer,
        Timeout:      cfg.DNS.Timeout,
    }
    
    // Services are created with explicit dependencies
    dnsResolver := dns.NewResolver(dnsConfig)
    httpAnalyzer := httpAnalyzer.NewAnalyzer(httpConfig)
    
    return &handlers.Dependencies{
        DNSResolver:  dnsResolver,
        HTTPAnalyzer: httpAnalyzer,
        // ... other services
    }
}
```

### 2. Configuration Management (`internal/config/`)

**Purpose**: Centralized configuration with environment variable support.

**Why it exists:**
- Single source of truth for all configuration
- Easy deployment configuration changes
- Type-safe configuration with validation
- Support for different environments (dev, staging, prod)

**Key features:**
- Environment variable parsing with defaults
- Configuration validation
- Structured configuration objects per service
- Support for timeouts, URLs, and other complex types

### 3. HTTP Handlers (`internal/handlers/`)

**Purpose**: HTTP request handling and API endpoint management.

**Architecture components:**

#### Handler Structure
```go
type Handler struct {
    service Service    // Business logic interface
    config  *Config   // Handler-specific configuration
}
```

#### Service Interface
```go
type Service interface {
    AnalyzeDomain(domain string, useCachedDNS bool) (*httpAnalyzer.AnalysisResult, error)
}
```

**Key responsibilities:**
- HTTP request parsing and validation
- Domain normalization (handling URLs with paths)
- JSON response serialization
- Error handling and status codes
- CORS header management
- Security header injection

**Design decisions:**
- **Interface-based design**: Handlers depend on interfaces, not concrete implementations
- **Separation of concerns**: Handlers focus on HTTP, services handle business logic
- **Consistent error handling**: All endpoints return structured JSON errors

### 4. DNS Resolution (`internal/dns/`)

**Purpose**: Domain name resolution with caching options.

**Why this component exists:**
- DNS resolution is foundational to all other analysis
- Need to support both system DNS and custom DNS servers
- Caching behavior affects analysis results
- TTL information is valuable for infrastructure analysis

**Key features:**
- System DNS vs. Google DNS (8.8.8.8) options
- CNAME and A record resolution
- TTL extraction and reporting
- Timeout handling for slow DNS responses

**Architecture:**
```go
type Resolver interface {
    ResolveCNAME(domain string) ([]string, error)
    ResolveA(domain string) ([]dns.ARecord, error)
}

type Config struct {
    UseCachedDNS bool
    DNSServer    string
    Timeout      time.Duration
}
```

### 5. HTTP Analysis (`internal/http/`)

**Purpose**: Comprehensive HTTP request analysis and server fingerprinting.

**This is the largest and most complex component because:**
- HTTP analysis requires multiple types of detection
- Server fingerprinting involves pattern matching across many server types
- CDN detection requires analyzing headers, responses, and timing
- Keep-alive analysis involves parsing specific HTTP headers

#### Sub-components:

**HTTP Analyzer (`analyzer.go`)**
- Manages HTTP requests to multiple IP addresses
- Handles redirects and timeouts
- Extracts timing information
- Coordinates between header analysis and server detection

**Header Analysis (`headers.go`)**
- CDN detection with confidence scoring
- Server header parsing
- Keep-alive parameter extraction
- Response header comparison across multiple servers

**Server Fingerprinting (`fingerprint.go`)**
- Pattern-based server identification
- Version detection from headers and responses
- Platform detection (Linux, Windows, etc.)
- Confidence scoring based on evidence quality

**Types and Structures (`types.go`)**
- Comprehensive data structures for all analysis results
- CDN detection results with evidence tracking
- Server fingerprinting results with confidence levels
- Response timing and connection information

**Key design patterns:**
- **Strategy Pattern**: Different detection methods for CDNs and servers
- **Builder Pattern**: Constructing complex analysis results
- **Factory Pattern**: Creating different types of analyzers

### 6. TCP Analysis (`internal/tcp/`)

**Purpose**: Low-level TCP connection analysis.

**Why TCP analysis matters:**
- TCP behavior reveals infrastructure details
- Connection timing indicates network quality
- TCP flags show connection establishment patterns
- Useful for detecting load balancers and proxies

**What it analyzes:**
- TCP handshake timing
- Connection establishment success/failure
- TCP flags (SYN, ACK, FIN, RST, etc.)
- Connection quality metrics
- Network latency patterns

**Design approach:**
- **Connection-based**: Analyzes actual TCP connections, not packet inspection
- **Timeout handling**: Graceful handling of slow or failed connections
- **Quality scoring**: Converts raw metrics into human-readable quality indicators

### 7. Content Security Policy (`internal/csp/`)

**Purpose**: CSP header analysis and security recommendations.

**CSP analysis components:**
- **Policy parsing**: Breaking down CSP directives
- **Security scoring**: Rating the effectiveness of policies
- **Recommendation engine**: Suggesting improvements
- **Compliance checking**: Validating against security best practices

**Why CSP matters:**
- CSP is a critical security feature for web applications
- Many websites have weak or missing CSP policies
- Analysis helps identify security vulnerabilities
- Recommendations help improve security posture

## Data Flow

### Analysis Request Flow

1. **Request Reception**
   ```text
   User Input → Handler → Validation → Service
   ```

2. **Domain Resolution**
   ```text
   Service → DNS Resolver → CNAME/A Records → IP List
   ```

3. **Parallel Analysis**
   ```text
   For each IP:
   ├── HTTP Analyzer → Headers, Keep-Alive, Server Info
   ├── TCP Analyzer → Connection Quality, Timing
   └── CSP Evaluator → Security Policy Analysis
   ```

4. **Result Aggregation**
   ```text
   Individual Results → Consolidation → Final Report
   ```

5. **Response Generation**
   ```text
   Final Report → JSON Serialization → HTTP Response
   ```

### Error Handling Strategy

**Graceful Degradation**: If one analysis component fails, others continue.

**Error Categorization:**
- **Network errors**: DNS resolution failures, connection timeouts
- **Application errors**: Invalid domains, malformed responses  
- **System errors**: Resource exhaustion, configuration issues

**Error Response Format:**
```json
{
    "error": "Human-readable description",
    "status": 400,
    "details": "Technical details for debugging"
}
```

## Key Design Decisions

### 1. Interface-Driven Design

**Decision**: All major components are defined by interfaces.

**Why**: 
- Enables easy testing with mock implementations
- Allows for future alternative implementations
- Reduces coupling between components
- Makes the code more maintainable

**Example**:
```go
type Analyzer interface {
    AnalyzeHTTP(domain string, ips []string) ([]Response, error)
}

// Multiple implementations possible:
// - RealHTTPAnalyzer (production)
// - MockHTTPAnalyzer (testing)
// - CachedHTTPAnalyzer (with caching)
```

### 2. Configuration-Driven Behavior

**Decision**: All timeouts, servers, and behavior are configurable.

**Why**:
- Different deployment environments have different requirements
- Users need control over timeout behavior
- Testing requires different configurations
- Production deployments need tuning capabilities

### 3. Parallel Analysis

**Decision**: DNS, HTTP, TCP, and CSP analysis happen concurrently where possible.

**Why**:
- Significantly reduces total analysis time
- Better resource utilization
- Improved user experience
- Scalability for multiple domains

### 4. Comprehensive Error Context

**Decision**: Errors include context about what was being attempted.

**Why**:
- Easier debugging for users and developers
- Better user experience with actionable error messages
- Helps identify network vs. application issues
- Supports troubleshooting documentation

### 5. Structured Logging

**Decision**: Use structured logging throughout the application.

**Why**:
- Better operational visibility
- Easier log parsing and analysis
- Consistent log format across components
- Support for log aggregation systems

## Security Considerations

### Input Validation
- All domain inputs are validated and normalized
- URL parsing prevents injection attacks
- Timeouts prevent resource exhaustion attacks

### Rate Limiting
- Built-in timeouts for all network operations
- Configurable retry limits
- Resource cleanup on cancellation

### Information Disclosure
- No sensitive information logged
- Error messages don't reveal internal details
- Security headers on all responses

## Performance Characteristics

### Memory Usage
- Streaming JSON parsing where possible
- Limited buffer sizes for network operations
- Garbage collection friendly object lifecycle

### CPU Usage
- Parallel processing for independent operations
- Efficient string processing for header analysis
- Minimal regex usage (compiled once, used multiple times)

### Network Usage
- Configurable timeouts prevent hanging connections
- Connection reuse where appropriate
- Minimal number of requests per analysis

## Testing Strategy

### Unit Testing
- Each component tested in isolation
- Mock implementations for external dependencies
- Edge case testing for error conditions

### Integration Testing
- End-to-end API testing
- Real network testing with known domains
- Performance testing with load simulation

### Security Testing
- Input validation testing
- Resource exhaustion testing
- Error handling validation

## Monitoring and Observability

### Metrics
- Request/response timing
- Error rates by component
- Resource usage patterns

### Logging
- Structured logs for all operations
- Error context and stack traces
- Performance metrics

### Health Checks
- Component health verification
- Dependency availability checking
- Resource usage monitoring

## Extension Points

### Adding New Analysis Types

1. Create a new package in `internal/`
2. Define an interface for the new analyzer
3. Implement the interface with configuration support
4. Add the analyzer to the dependency injection in `main.go`
5. Update the response types to include new analysis results

### Adding New CDN Providers

1. Add detection logic in `internal/http/headers.go`
2. Update the CDN mapping in the frontend
3. Add test cases for the new provider
4. Update documentation

### Adding New Server Types

1. Extend the fingerprinting patterns in `internal/http/fingerprint.go`
2. Add version detection logic
3. Update confidence scoring
4. Add test cases

This architecture provides a solid foundation for the current functionality while remaining flexible enough to accommodate future enhancements and requirements.