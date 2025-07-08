# HTTP Keep-Alive Analyzer

A web server fingerprinting and analysis tool that helps understand how web servers handle connections, what technologies they use, and how they're configured.

## What Does This Tool Do?

Think of this as a "health check" for websites, but much more detailed. When you visit a website, your browser makes an HTTP connection to a server. This tool analyzes that connection process to reveal:

- **How long the server keeps connections open** (Keep-Alive settings)
- **What web server software is running** (Apache, Nginx, etc.)
- **If there's a CDN in front of the server** (Cloudflare, AWS CloudFront, etc.)
- **DNS configuration details** (how the domain name resolves to IP addresses)
- **Security policies** (Content Security Policy analysis)
- **Low-level network details** (TCP connection behavior)

This information is valuable for security researchers, system administrators, and developers who want to understand web infrastructure.

## Features

- **HTTP Keep-Alive Analysis**: Detects keep-alive timeout settings and connection behavior
- **DNS Resolution**: Analyzes CNAME and A records with TTL information
- **TCP Connection Analysis**: Low-level TCP connection details and handshake analysis
- **CDN Detection**: Identifies popular CDN providers with confidence levels
- **Server Fingerprinting**: Determines server type, version, and platform
- **Content Security Policy (CSP)**: Evaluates and recommends optimal CSP headers
- **Web Interface**: Modern, accessible web UI with dark mode support
- **JSON API**: RESTful API endpoints for programmatic access

## Quick Start

### Running the Application

You have two options: run it locally or use Docker.

#### Option 1: Run Locally (Requires Go)

```bash
# Clone the repository
git clone <repository-url>
cd http-keepalive

# Build the application
go build -o http-keepalive main.go

# Start the server
./http-keepalive
```

#### Option 2: Run with Docker

```bash
# Build the Docker image
docker build -t http-keepalive .

# Run the container
docker run -p 3000:3000 http-keepalive
```

Once running, open your browser to `http://localhost:3000`.

### Using the Web Interface

1. **Enter a domain**: Type any website (like `google.com` or `https://example.com`)
2. **Choose DNS option**: Decide whether to use your system's DNS cache or bypass it
3. **Click "Analyze"**: The tool will connect to the server and gather information
4. **Explore the results**: Use the tabs to see different aspects of the analysis

## Understanding the Results

### Summary Tab

Shows the big picture: server type, response time, CDN detection, and an overview chart of performance metrics.

### DNS Tab

Reveals how the domain name translates to IP addresses:

- **CNAME records**: Domain aliases (like <www.example.com> pointing to example.com)
- **A records**: The actual IP addresses the domain resolves to
- **TTL values**: How long DNS resolvers should cache this information

### Headers Tab

Displays the HTTP headers sent by the server, which reveal configuration details and can highlight differences between multiple servers (useful for load-balanced setups).

### TCP Analysis Tab

Shows low-level network connection details:

- **Connection timing**: How long it takes to establish a connection
- **TCP flags**: Technical details about how the connection was established
- **Quality metrics**: Whether the connection is performing well

### Security Policy Tab

Analyzes the website's Content Security Policy (CSP):

- **Current policy**: What security restrictions are in place
- **Recommendations**: Suggestions for improving security
- **Risk assessment**: Potential security vulnerabilities

## API Documentation

The tool provides REST API endpoints for programmatic access. This means you can integrate it into your own applications or scripts.

### API Endpoints Overview

| Endpoint | Method | Purpose | Domain Required |
|----------|---------|---------|----------------|
| `/api/health` | GET | Check if the service is running | ❌ No |
| `/api/analyze` | GET | Analyze a domain via URL parameters | ✅ Yes |
| `/api/analyze` | POST | Analyze a domain via JSON request | ✅ Yes |

### Health Check Endpoint

**Purpose**: Verify the service is running and discover available endpoints.

```bash
GET /api/health
```

**No parameters needed.** This endpoint doesn't analyze any domain—it just tells you if the service is working.

**Example request:**

```bash
curl http://localhost:3000/api/health
```

**Example response:**

```json
{
  "status": "ok",
  "service": "HTTP Keep-Alive Analyzer",
  "version": "2.0",
  "endpoints": {
    "analyze_get": "/api/analyze?domain=example.com&useCachedDns=false",
    "analyze_post": "/api/analyze (POST with JSON body)",
    "health": "/api/health"
  }
}
```

### Domain Analysis Endpoints

**Purpose**: Perform the actual analysis of a website. These endpoints require a domain parameter.

#### GET Method (Query Parameters)

Use this when you want to analyze a domain with a simple HTTP GET request.

```bash
GET /api/analyze?domain=example.com&useCachedDns=false
```

**Parameters:**

- `domain` (required): The website to analyze (e.g., `google.com`, `https://example.com/path`)
- `useCachedDns` (optional): Whether to use your system's DNS cache (`true` or `false`, defaults to `false`)

**Example request:**

```bash
curl "http://localhost:3000/api/analyze?domain=google.com&useCachedDns=false"
```

#### POST Method (JSON Body)

Use this when you're calling the API from an application and want to send structured data.

```bash
POST /api/analyze
Content-Type: application/json
```

**Request body:**

```json
{
  "domain": "example.com",
  "useCachedDns": false
}
```

**Example request:**

```bash
curl -X POST http://localhost:3000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"domain":"google.com","useCachedDns":false}'
```

### Understanding API Responses

Both GET and POST methods return the same JSON structure. Here's what each section contains:

```json
{
  "cnameRecords": ["www.example.com."],
  "aRecords": [
    {
      "ip": "93.184.216.34",
      "ttl": 600000000000
    }
  ],
  "stableHeaders": {
    "Server": "ECS (nyb/1D2E)",
    "Content-Type": "text/html; charset=UTF-8",
    "Cache-Control": "max-age=604800"
  },
  "differentHeadersFound": false,
  "responses": [
    {
      "domain": "93.184.216.34",
      "keepAliveTimeout": "60",
      "requestDuration": 150,
      "tlsVersion": "TLS 1.3",
      "serverHeader": "ECS (nyb/1D2E)",
      "cdnDetections": {
        "cloudflare": {
          "provider": "Cloudflare",
          "detected": false,
          "confidence": "Low",
          "evidence": [],
          "primaryEvidence": ""
        }
      },
      "serverInfo": {
        "serverType": "Apache",
        "version": "2.4.41",
        "platform": "Linux",
        "confidence": "High",
        "fingerprint": "Server:Apache/2.4.41;"
      },
      "tcpResults": "{ ... TCP connection details ... }",
      "cspDetails": "=== CSP Analysis Results ===",
      "responseHeaders": {
        "Server": ["ECS (nyb/1D2E)"],
        "Content-Type": ["text/html; charset=UTF-8"]
      }
    }
  ]
}
```

### Error Handling

API endpoints return structured error responses:

```json
{
  "error": "Missing 'domain' parameter",
  "status": 400
}
```

Common error codes:

- `400`: Bad Request (invalid domain, missing parameters)
- `405`: Method Not Allowed
- `500`: Internal Server Error (analysis failed)

### CORS Support

The API includes Cross-Origin Resource Sharing (CORS) headers, which means you can call it from web applications running on different domains.

#### Key Response Fields Explained

**DNS Information:**

- `cnameRecords`: Domain aliases (redirects from one domain to another)
- `aRecords`: IP addresses and their cache duration (TTL)

**CDN Detection:**

- `detected`: Whether a CDN was found
- `confidence`: How sure we are (High, Medium, Low)
- `evidence`: What clues led to this detection
- `provider`: Which CDN service (Cloudflare, AWS CloudFront, etc.)

**Server Fingerprinting:**

- `serverType`: Web server software (Apache, Nginx, IIS, etc.)
- `version`: Software version if detectable
- `platform`: Operating system/platform
- `confidence`: How certain the detection is

**Performance Metrics:**

- `requestDuration`: How long the request took (in milliseconds)
- `keepAliveTimeout`: How long the server keeps connections open
- `tlsVersion`: Which version of TLS/SSL is being used

## Technical Details

### What is HTTP Keep-Alive?

HTTP Keep-Alive is a feature that allows multiple HTTP requests to reuse the same TCP connection. Without it, each request would need to establish a new connection, which is slower and uses more resources.

**Key concepts:**

- **Keep-Alive Timeout**: How long the server waits before closing an idle connection
- **Max Requests**: How many requests can use the same connection
- **Connection Reuse**: Multiple requests sharing one TCP connection

### TCP Flags Reference

When analyzing TCP connections, you'll see various flags that indicate different states:

- **SYN** (Synchronize): "Let's start a connection" - begins the handshake
- **ACK** (Acknowledge): "I received your message" - confirms receipt
- **FIN** (Finish): "I'm done sending data" - begins connection termination
- **RST** (Reset): "Something went wrong, reset the connection" - aborts connection
- **PSH** (Push): "Process this data immediately" - urgent data
- **URG** (Urgent): "This data is high priority" - rarely used
- **ECE** (ECN Echo): "I detected network congestion" - traffic management
- **CWR** (Congestion Window Reduced): "I'm slowing down due to congestion" - traffic control

### CDN Detection Methods

The tool identifies CDNs (Content Delivery Networks) by analyzing:

1. **HTTP Headers**: Special headers that CDNs add
2. **Server Responses**: Unique response patterns
3. **DNS Records**: CDN-specific DNS configurations
4. **TLS Certificates**: Certificate authorities commonly used by CDNs

### Security Policy Analysis

Content Security Policy (CSP) is a security feature that helps prevent cross-site scripting (XSS) attacks. The tool analyzes:

- **Current policy**: What restrictions are in place
- **Policy effectiveness**: How well it protects against attacks
- **Recommendations**: Suggestions for improvement
- **Compatibility**: Whether the policy works across different browsers

## Configuration Options

You can customize the tool's behavior through environment variables:

```bash
# Server configuration
PORT=3000                    # Port to run the server on
PUBLIC_DIR=./public         # Directory containing web assets

# DNS settings
DNS_TIMEOUT=5s              # How long to wait for DNS responses
DNS_SERVER=8.8.8.8         # DNS server to use for queries

# HTTP analysis settings
HTTP_TIMEOUT=30s            # Timeout for HTTP requests
HTTP_USER_AGENT="HTTP Keep-Alive Analyzer/2.0"  # User agent string
HTTP_MAX_REDIRECTS=5        # Maximum redirects to follow

# TCP analysis settings
TCP_TIMEOUT=10s             # Timeout for TCP connections
TCP_RETRIES=3               # Number of connection attempts

# CSP analysis settings
CSP_TIMEOUT=30s             # Timeout for CSP analysis
CSP_MAX_DEPTH=3             # How deep to analyze page resources
```

## Deployment

### Docker Deployment

The recommended way to deploy this tool is using Docker:

```bash
# Build the image
docker build -t http-keepalive .

# Run in production
docker run -d \
  --name http-keepalive \
  -p 3000:3000 \
  --restart unless-stopped \
  http-keepalive
```

### Manual Deployment

If you prefer to run it directly:

```bash
# Build for production
go build -ldflags="-w -s" -o http-keepalive main.go

# Run with production settings
PORT=3000 ./http-keepalive
```

## Development

### Prerequisites

- Go 1.21 or later
- Basic understanding of HTTP, DNS, and networking concepts

### Building and Testing

```bash
# Install dependencies
go mod download

# Build the application
go build -o http-keepalive main.go

# Run tests (if available)
go test ./...

# Run with development settings
go run main.go
```

### Project Structure

```text
├── main.go                 # Application entry point
├── internal/               # Internal packages (not importable by other projects)
│   ├── config/            # Configuration management
│   ├── dns/               # DNS resolution logic
│   ├── handlers/          # HTTP request handlers and API endpoints
│   ├── http/              # HTTP analysis and fingerprinting
│   ├── tcp/               # TCP connection analysis
│   └── csp/               # Content Security Policy evaluation
├── public/                # Web interface files
│   ├── index.html         # Main web page
│   ├── app.js             # Frontend JavaScript
│   └── styles.css         # Styling
├── Dockerfile             # Container configuration
├── go.mod                 # Go module dependencies
└── README.md              # This file
```

### Contributing

When contributing to this project:

1. Follow Go best practices and idioms
2. Write tests for new functionality
3. Update documentation for any changes
4. Ensure the web interface remains accessible
5. Test with various types of websites (CDNs, load balancers, etc.)

## Troubleshooting

### Common Issues

**"Connection refused" errors:**

- Check if the target website is accessible
- Verify your internet connection
- Some websites block automated requests

**DNS resolution failures:**

- Try using a different DNS server
- Check if the domain exists
- Verify your network allows DNS queries

**Slow analysis:**

- Some servers have intentional delays
- Network latency can affect results
- Complex websites take longer to analyze

**Missing data in results:**

- Not all servers provide complete information
- Some details are only available over HTTPS
- Firewalls may block certain types of analysis

### Getting Help

If you encounter issues:

1. Check the application logs for error messages
2. Verify your network configuration
3. Test with a simple website like `google.com`
4. Check if the issue is specific to certain domains

## License and Security

This tool is designed for legitimate security research and system administration. Always ensure you have permission to analyze the systems you're testing.

**Responsible use:**

- Only analyze systems you own or have explicit permission to test
- Respect rate limits and don't overwhelm target servers
- Be aware that some organizations may consider this tool as reconnaissance
- Follow your organization's security policies

## Documentation

For more detailed information, see additional documentation:

- **[Architecture Documentation](docs/ARCHITECTURE.md)** - Detailed explanation of the codebase structure, components, and design decisions
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Complete deployment instructions for development, staging, and production environments
- **API Documentation** - Available in the web interface under the "API Documentation" tab

## What's Next?

This tool provides a foundation for understanding web server infrastructure. You might want to:

- Integrate it into your monitoring systems
- Use it for security assessments
- Build custom analysis workflows
- Extend it with additional fingerprinting techniques

The modular architecture makes it easy to add new analysis methods or customize existing ones for your specific needs.

## Contributing to the Project

I welcome contributions!
