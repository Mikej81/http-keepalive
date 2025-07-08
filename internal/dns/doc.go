// Package dns provides DNS resolution functionality for the HTTP keepalive analyzer.
//
// This package implements DNS resolution with support for both system DNS
// and custom DNS servers. It provides interfaces for dependency injection
// and testability.
//
// Key features:
//   - CNAME and A record resolution
//   - TTL information preservation
//   - System DNS server detection
//   - Configurable timeouts
//   - Error handling with proper error types
//
// Example usage:
//
//	config := &dns.Config{
//		UseCachedDNS: false,
//		DNSServer:    "8.8.8.8:53",
//		Timeout:      5 * time.Second,
//	}
//	resolver := dns.NewResolver(config)
//	result, err := resolver.ResolveDomain("example.com")
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("Found %d A records\n", len(result.ARecords))
package dns