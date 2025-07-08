// Package errors provides application-specific error types and handling.
//
// This package implements a comprehensive error handling system with:
//   - Typed errors for different failure scenarios
//   - Error wrapping with additional context
//   - Error classification and inspection utilities
//   - Structured error information for APIs
//
// The package helps improve error handling by:
//   - Providing clear error categorization
//   - Enabling proper error recovery strategies
//   - Supporting error chain inspection
//   - Facilitating structured logging and monitoring
//
// Key features:
//   - Domain-specific error types (DNS, HTTP, TCP, CSP)
//   - Error wrapping with operational context
//   - Error classification helpers
//   - Retry logic support through error type inspection
//   - Structured error information for JSON APIs
//
// Example usage:
//
//	err := errors.NewDNSNotFoundError("example.com")
//	if errors.IsDNSError(err) {
//		log.Printf("DNS resolution failed: %v", err)
//	}
//
//	wrappedErr := errors.Wrap(err, errors.ErrorTypeHTTPRequest, "domain analysis")
//	if errors.IsRetryableError(wrappedErr) {
//		// Implement retry logic
//	}
package errors