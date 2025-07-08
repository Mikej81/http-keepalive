// Package csp provides Content Security Policy generation functionality.
//
// This package analyzes web pages and generates appropriate CSP headers
// by examining HTML elements and their resource dependencies.
//
// The CSP generator helps improve web application security by:
//   - Identifying external resource domains
//   - Detecting inline scripts and styles
//   - Generating appropriate CSP directives
//   - Supporting various HTML elements (script, link, img, video, etc.)
//
// Key features:
//   - HTML parsing and resource extraction
//   - Support for all CSP directive types
//   - Inline content detection
//   - Relative URL resolution
//   - Configurable analysis depth
//
// Example usage:
//
//	config := &csp.Config{
//		Timeout:         30 * time.Second,
//		MaxDepth:        1,
//		FollowRedirects: true,
//	}
//	generator := csp.NewGenerator(config)
//	policy, err := generator.GenerateCSP("https://example.com")
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("Generated CSP: %s\n", policy)
package csp