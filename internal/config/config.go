package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds the application configuration
type Config struct {
	Server   ServerConfig   `json:"server"`
	DNS      DNSConfig      `json:"dns"`
	HTTP     HTTPConfig     `json:"http"`
	TCP      TCPConfig      `json:"tcp"`
	CSP      CSPConfig      `json:"csp"`
	Logging  LoggingConfig  `json:"logging"`
}

// ServerConfig holds server-related configuration
type ServerConfig struct {
	Port         string        `json:"port"`
	Host         string        `json:"host"`
	PublicDir    string        `json:"publicDir"`
	ReadTimeout  time.Duration `json:"readTimeout"`
	WriteTimeout time.Duration `json:"writeTimeout"`
	IdleTimeout  time.Duration `json:"idleTimeout"`
}

// DNSConfig holds DNS resolver configuration
type DNSConfig struct {
	DefaultServer string        `json:"defaultServer"`
	Timeout       time.Duration `json:"timeout"`
	UseCachedDNS  bool          `json:"useCachedDns"`
}

// HTTPConfig holds HTTP client configuration
type HTTPConfig struct {
	Timeout             time.Duration `json:"timeout"`
	MaxRedirects        int           `json:"maxRedirects"`
	InsecureSkipVerify  bool          `json:"insecureSkipVerify"`
	UserAgent           string        `json:"userAgent"`
}

// TCPConfig holds TCP analyzer configuration
type TCPConfig struct {
	Timeout     time.Duration `json:"timeout"`
	MaxRetries  int           `json:"maxRetries"`
	RetryDelay  time.Duration `json:"retryDelay"`
	BufferSize  int           `json:"bufferSize"`
}

// CSPConfig holds CSP generator configuration
type CSPConfig struct {
	Timeout         time.Duration `json:"timeout"`
	UserAgent       string        `json:"userAgent"`
	MaxDepth        int           `json:"maxDepth"`
	FollowRedirects bool          `json:"followRedirects"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

// Load loads configuration from environment variables with defaults
func Load() *Config {
	return &Config{
		Server: ServerConfig{
			Port:         getEnvOrDefault("HTTP_PORT", ":3000"),
			Host:         getEnvOrDefault("HTTP_HOST", "localhost"),
			PublicDir:    getEnvOrDefault("PUBLIC_DIR", "public"),
			ReadTimeout:  getDurationOrDefault("READ_TIMEOUT", 30*time.Second),
			WriteTimeout: getDurationOrDefault("WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:  getDurationOrDefault("IDLE_TIMEOUT", 60*time.Second),
		},
		DNS: DNSConfig{
			DefaultServer: getEnvOrDefault("DNS_SERVER", "8.8.8.8:53"),
			Timeout:       getDurationOrDefault("DNS_TIMEOUT", 5*time.Second),
			UseCachedDNS:  getBoolOrDefault("USE_CACHED_DNS", false),
		},
		HTTP: HTTPConfig{
			Timeout:            getDurationOrDefault("HTTP_TIMEOUT", 30*time.Second),
			MaxRedirects:       getIntOrDefault("HTTP_MAX_REDIRECTS", 10),
			InsecureSkipVerify: getBoolOrDefault("HTTP_INSECURE_SKIP_VERIFY", true),
			UserAgent:          getEnvOrDefault("HTTP_USER_AGENT", "HTTP-KeepAlive-Analyzer/1.0"),
		},
		TCP: TCPConfig{
			Timeout:    getDurationOrDefault("TCP_TIMEOUT", 15*time.Second),
			MaxRetries: getIntOrDefault("TCP_MAX_RETRIES", 10),
			RetryDelay: getDurationOrDefault("TCP_RETRY_DELAY", 1*time.Second),
			BufferSize: getIntOrDefault("TCP_BUFFER_SIZE", 4096),
		},
		CSP: CSPConfig{
			Timeout:         getDurationOrDefault("CSP_TIMEOUT", 30*time.Second),
			UserAgent:       getEnvOrDefault("CSP_USER_AGENT", "CSP-Generator/1.0"),
			MaxDepth:        getIntOrDefault("CSP_MAX_DEPTH", 1),
			FollowRedirects: getBoolOrDefault("CSP_FOLLOW_REDIRECTS", true),
		},
		Logging: LoggingConfig{
			Level:  getEnvOrDefault("LOG_LEVEL", "info"),
			Format: getEnvOrDefault("LOG_FORMAT", "text"),
		},
	}
}

// Helper functions for environment variable parsing

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getDurationOrDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

func getIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Server.Port == "" {
		return newValidationError("server.port", "port is required")
	}
	
	if c.DNS.DefaultServer == "" {
		return newValidationError("dns.defaultServer", "default DNS server is required")
	}
	
	if c.HTTP.Timeout <= 0 {
		return newValidationError("http.timeout", "timeout must be positive")
	}
	
	if c.TCP.MaxRetries < 0 {
		return newValidationError("tcp.maxRetries", "max retries cannot be negative")
	}
	
	return nil
}

// newValidationError creates a validation error
func newValidationError(field, message string) error {
	return &ValidationError{
		Field:   field,
		Message: message,
	}
}

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return "config validation failed for " + e.Field + ": " + e.Message
}