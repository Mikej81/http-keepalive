// Package tcp provides TCP handshake analysis functionality.
//
// This package implements low-level TCP connection analysis including:
//   - TCP handshake analysis
//   - TCP option parsing
//   - Connection retry logic with exponential backoff
//   - Support for both TCP and TLS connections
//
// The analyzer provides detailed information about TCP connections
// that complement the HTTP-level analysis.
//
// Key features:
//   - Raw TCP packet parsing
//   - TCP option identification (MSS, Window Scale, SACK, Timestamps)
//   - Automatic fallback to TLS connections
//   - Configurable retry mechanisms
//   - Detailed error reporting
//
// Example usage:
//
//	config := &tcp.Config{
//		Timeout:    15 * time.Second,
//		MaxRetries: 10,
//		RetryDelay: 1 * time.Second,
//	}
//	analyzer := tcp.NewAnalyzer(config)
//	result, err := analyzer.AnalyzeHandshake("example.com:443")
//	if err != nil {
//		log.Fatal(err)
//	}
//	if result.TCPResponse != nil {
//		fmt.Printf("TCP Window Size: %d\n", result.TCPResponse.WindowSize)
//	}
package tcp