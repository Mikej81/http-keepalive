// Package handlers provides HTTP request handlers and service orchestration.
//
// This package implements the web interface for the HTTP keepalive analyzer,
// including REST API endpoints and static file serving. It orchestrates
// the various analysis services (DNS, HTTP, TCP, CSP) to provide comprehensive
// domain analysis.
//
// The package follows clean architecture principles by:
//   - Separating HTTP concerns from business logic
//   - Using dependency injection for testability
//   - Providing clear service interfaces
//   - Implementing proper error handling and logging
//
// Key features:
//   - RESTful API endpoints for domain analysis
//   - Static file serving for web interface
//   - Request validation and normalization
//   - Service orchestration and dependency injection
//   - Graceful error handling and logging
//
// Example usage:
//
//	deps := &handlers.Dependencies{
//		DNSResolver:  dnsResolver,
//		HTTPAnalyzer: httpAnalyzer,
//		TCPAnalyzer:  tcpAnalyzer,
//		CSPGenerator: cspGenerator,
//	}
//	service := handlers.NewAnalysisService(deps)
//	handler := handlers.New(service, config)
//	handler.SetupRoutes(mux)
package handlers