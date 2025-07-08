# Multi-stage build for Go application
# Use the official Go image with a specific version for reproducible builds
FROM golang:1.21-alpine AS builder

LABEL maintainer="Michael Coleman Michael@f5.com" \
      version="2.0" \
      description="HTTP Keep-Alive Analyzer - Refactored version with modern Go practices"

# Install security updates and certificates
RUN apk update && apk add --no-cache \
    ca-certificates \
    git \
    && rm -rf /var/cache/apk/*

# Create non-root user for security
RUN adduser -D -s /bin/sh appuser

# Set working directory
WORKDIR /app

# Copy dependency files first for better Docker layer caching
COPY go.mod go.sum ./

# Download dependencies with verification
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the application with security flags
# -trimpath removes file system paths from executable
# -ldflags="-w -s" strips debug information to reduce size
# CGO_ENABLED=0 creates a static binary
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

RUN go build \
    -trimpath \
    -ldflags="-w -s -X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')" \
    -o http-keepalive \
    ./main.go

# Production image with minimal attack surface
FROM alpine:3.19

# Install security updates and minimal runtime dependencies
RUN apk update && apk add --no-cache \
    ca-certificates \
    tzdata \
    && rm -rf /var/cache/apk/* \
    && update-ca-certificates

# Create non-root user
RUN addgroup -g 1000 appgroup && \
    adduser -D -s /bin/sh -u 1000 -G appgroup appuser

# Create application directory
WORKDIR /app

# Copy binary and static files with proper ownership
COPY --from=builder --chown=appuser:appgroup /app/http-keepalive ./
COPY --from=builder --chown=appuser:appgroup /app/public ./public

# Ensure binary is executable
RUN chmod +x ./http-keepalive

# Switch to non-root user
USER appuser

# Create health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/ || exit 1

# Expose port
EXPOSE 3000

# Set environment variables for production
ENV GIN_MODE=release \
    LOG_LEVEL=info

# Run the application
CMD ["./http-keepalive"]