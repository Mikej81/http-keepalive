package errors

import (
	"fmt"
	"net"
)

// ErrorType represents different types of errors
type ErrorType string

const (
	// DNS-related errors
	ErrorTypeDNSResolution ErrorType = "dns_resolution"
	ErrorTypeDNSTimeout    ErrorType = "dns_timeout"
	ErrorTypeDNSNotFound   ErrorType = "dns_not_found"
	
	// HTTP-related errors
	ErrorTypeHTTPRequest  ErrorType = "http_request"
	ErrorTypeHTTPTimeout  ErrorType = "http_timeout"
	ErrorTypeHTTPResponse ErrorType = "http_response"
	
	// TCP-related errors
	ErrorTypeTCPConnection ErrorType = "tcp_connection"
	ErrorTypeTCPHandshake  ErrorType = "tcp_handshake"
	ErrorTypeTCPTimeout    ErrorType = "tcp_timeout"
	
	// CSP-related errors
	ErrorTypeCSPGeneration ErrorType = "csp_generation"
	ErrorTypeCSPParsing    ErrorType = "csp_parsing"
	
	// Validation errors
	ErrorTypeValidation ErrorType = "validation"
	ErrorTypeInvalidURL ErrorType = "invalid_url"
	
	// Configuration errors
	ErrorTypeConfiguration ErrorType = "configuration"
	
	// General errors
	ErrorTypeInternal ErrorType = "internal"
	ErrorTypeUnknown  ErrorType = "unknown"
)

// AppError represents an application-specific error
type AppError struct {
	Type      ErrorType `json:"type"`
	Message   string    `json:"message"`
	Cause     error     `json:"-"`
	Operation string    `json:"operation,omitempty"`
	Domain    string    `json:"domain,omitempty"`
	Code      string    `json:"code,omitempty"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Operation, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Operation, e.Message)
}

// Unwrap returns the underlying error
func (e *AppError) Unwrap() error {
	return e.Cause
}

// Is checks if the error is of a specific type
func (e *AppError) Is(target error) bool {
	if targetErr, ok := target.(*AppError); ok {
		return e.Type == targetErr.Type
	}
	return false
}

// New creates a new application error
func New(errorType ErrorType, message string) *AppError {
	return &AppError{
		Type:    errorType,
		Message: message,
	}
}

// Wrap wraps an existing error with additional context
func Wrap(err error, errorType ErrorType, operation string) *AppError {
	return &AppError{
		Type:      errorType,
		Message:   err.Error(),
		Cause:     err,
		Operation: operation,
	}
}

// Wrapf wraps an existing error with formatted message
func Wrapf(err error, errorType ErrorType, operation string, format string, args ...interface{}) *AppError {
	return &AppError{
		Type:      errorType,
		Message:   fmt.Sprintf(format, args...),
		Cause:     err,
		Operation: operation,
	}
}

// DNS-specific error constructors

// NewDNSNotFoundError creates a DNS not found error
func NewDNSNotFoundError(domain string) *AppError {
	return &AppError{
		Type:    ErrorTypeDNSNotFound,
		Message: fmt.Sprintf("domain not found: %s", domain),
		Domain:  domain,
	}
}

// NewDNSResolutionError creates a DNS resolution error
func NewDNSResolutionError(domain string, cause error) *AppError {
	return &AppError{
		Type:    ErrorTypeDNSResolution,
		Message: fmt.Sprintf("failed to resolve domain: %s", domain),
		Cause:   cause,
		Domain:  domain,
	}
}

// HTTP-specific error constructors

// NewHTTPRequestError creates an HTTP request error
func NewHTTPRequestError(url string, cause error) *AppError {
	return &AppError{
		Type:    ErrorTypeHTTPRequest,
		Message: fmt.Sprintf("HTTP request failed for URL: %s", url),
		Cause:   cause,
		Domain:  url,
	}
}

// NewHTTPTimeoutError creates an HTTP timeout error
func NewHTTPTimeoutError(url string) *AppError {
	return &AppError{
		Type:    ErrorTypeHTTPTimeout,
		Message: fmt.Sprintf("HTTP request timed out for URL: %s", url),
		Domain:  url,
	}
}

// TCP-specific error constructors

// NewTCPConnectionError creates a TCP connection error
func NewTCPConnectionError(target string, cause error) *AppError {
	return &AppError{
		Type:    ErrorTypeTCPConnection,
		Message: fmt.Sprintf("TCP connection failed for target: %s", target),
		Cause:   cause,
		Domain:  target,
	}
}

// NewTCPHandshakeError creates a TCP handshake error
func NewTCPHandshakeError(target string, cause error) *AppError {
	return &AppError{
		Type:    ErrorTypeTCPHandshake,
		Message: fmt.Sprintf("TCP handshake failed for target: %s", target),
		Cause:   cause,
		Domain:  target,
	}
}

// Validation error constructors

// NewValidationError creates a validation error
func NewValidationError(field string, message string) *AppError {
	return &AppError{
		Type:    ErrorTypeValidation,
		Message: fmt.Sprintf("validation failed for %s: %s", field, message),
		Code:    field,
	}
}

// NewInvalidURLError creates an invalid URL error
func NewInvalidURLError(url string) *AppError {
	return &AppError{
		Type:    ErrorTypeInvalidURL,
		Message: fmt.Sprintf("invalid URL: %s", url),
		Domain:  url,
	}
}

// Error classification functions

// IsDNSError checks if an error is DNS-related
func IsDNSError(err error) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Type == ErrorTypeDNSResolution || 
			   appErr.Type == ErrorTypeDNSTimeout || 
			   appErr.Type == ErrorTypeDNSNotFound
	}
	
	// Check for standard DNS errors
	if dnsErr, ok := err.(*net.DNSError); ok {
		return dnsErr.IsNotFound || dnsErr.IsTimeout || dnsErr.IsTemporary
	}
	
	return false
}

// IsHTTPError checks if an error is HTTP-related
func IsHTTPError(err error) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Type == ErrorTypeHTTPRequest || 
			   appErr.Type == ErrorTypeHTTPTimeout || 
			   appErr.Type == ErrorTypeHTTPResponse
	}
	return false
}

// IsTCPError checks if an error is TCP-related
func IsTCPError(err error) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Type == ErrorTypeTCPConnection || 
			   appErr.Type == ErrorTypeTCPHandshake || 
			   appErr.Type == ErrorTypeTCPTimeout
	}
	return false
}

// IsValidationError checks if an error is validation-related
func IsValidationError(err error) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Type == ErrorTypeValidation || 
			   appErr.Type == ErrorTypeInvalidURL
	}
	return false
}

// IsRetryableError checks if an error is potentially retryable
func IsRetryableError(err error) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Type == ErrorTypeHTTPTimeout || 
			   appErr.Type == ErrorTypeTCPTimeout || 
			   appErr.Type == ErrorTypeDNSTimeout
	}
	
	// Check for standard network errors
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout() || netErr.Temporary()
	}
	
	return false
}