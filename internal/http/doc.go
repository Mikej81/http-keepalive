// Package http provides HTTP analysis functionality for the keepalive analyzer.
//
// This package implements comprehensive HTTP request analysis including:
//   - Keep-alive timeout detection
//   - TLS version identification
//   - Header analysis and CDN detection
//   - Response time measurement
//   - Multi-IP analysis for load balancers
//
// The package follows the Single Responsibility Principle by separating
// HTTP analysis from DNS resolution, TCP analysis, and CSP generation.
//
// Key features:
//   - Configurable HTTP client with timeout and redirect handling
//   - Header analysis for CDN providers (Cloudflare, CloudFront, Akamai)
//   - Keep-alive timeout extraction
//   - Stable header identification across multiple responses
//   - Error handling with detailed error context
//
// Example usage:
//
//	config := &http.Config{
//		Timeout:            30 * time.Second,
//		InsecureSkipVerify: true,
//		MaxRedirects:       10,
//	}
//	analyzer := http.NewAnalyzer(config)
//	result, err := analyzer.AnalyzeDomain("https://example.com", dnsResult)
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("Analyzed %d responses\n", len(result.Responses))
package http