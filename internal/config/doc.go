// Package config provides application configuration management.
//
// This package implements configuration loading from environment variables
// with sensible defaults for all settings. It supports validation and
// structured configuration for all application components.
//
// The configuration system provides:
//   - Environment variable-based configuration
//   - Type-safe configuration structures
//   - Default values for all settings
//   - Configuration validation
//   - Organized configuration by functional area
//
// Key features:
//   - Server configuration (ports, timeouts, directories)
//   - DNS resolver configuration
//   - HTTP client configuration
//   - TCP analyzer configuration
//   - CSP generator configuration
//   - Logging configuration
//
// Example usage:
//
//	cfg := config.Load()
//	if err := cfg.Validate(); err != nil {
//		log.Fatalf("Configuration validation failed: %v", err)
//	}
//
//	// Use configuration values
//	server := &http.Server{
//		Addr:         cfg.Server.Port,
//		ReadTimeout:  cfg.Server.ReadTimeout,
//		WriteTimeout: cfg.Server.WriteTimeout,
//	}
//
// Environment variables:
//   - HTTP_PORT: Server port (default: ":3000")
//   - DNS_SERVER: Default DNS server (default: "8.8.8.8:53")
//   - HTTP_TIMEOUT: HTTP request timeout (default: "30s")
//   - TCP_TIMEOUT: TCP connection timeout (default: "15s")
//   - And many more...
package config