package http

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"http-keepalive/internal/dns"
)

const (
	defaultTimeout    = 30 * time.Second
	defaultMaxRedirects = 10
	defaultUserAgent  = "HTTP-KeepAlive-Analyzer/1.0"
)

// Client implements the Analyzer interface
type Client struct {
	config     *Config
	httpClient *http.Client
}

// NewAnalyzer creates a new HTTP analyzer with the given configuration
func NewAnalyzer(config *Config) *Client {
	if config == nil {
		config = &Config{
			Timeout:            defaultTimeout,
			InsecureSkipVerify: true,
			MaxRedirects:       defaultMaxRedirects,
			UserAgent:          defaultUserAgent,
		}
	}

	httpClient := &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: config.InsecureSkipVerify,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= config.MaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return &Client{
		config:     config,
		httpClient: httpClient,
	}
}

// AnalyzeDomain performs HTTP analysis for all A records of a domain
func (c *Client) AnalyzeDomain(domain string, dnsResult *dns.Result) (*AnalysisResult, error) {
	if len(dnsResult.ARecords) == 0 {
		return nil, fmt.Errorf("no A records found for domain")
	}

	var responses []Response
	parsedURL, err := url.Parse(domain)
	if err != nil {
		return nil, fmt.Errorf("invalid domain URL: %w", err)
	}

	originalHost := parsedURL.Hostname()

	// Analyze each A record
	for _, aRecord := range dnsResult.ARecords {
		// Replace hostname with IP address
		targetURL := strings.Replace(domain, originalHost, aRecord.IP, 1)
		
		response, err := c.makeRequestWithTCPAnalysis(targetURL, originalHost, aRecord, dnsResult)
		if err != nil {
			// Include error response for completeness
			responses = append(responses, Response{
				Domain:       aRecord.IP,
				Error:        err.Error(),
				CNAMERecords: dnsResult.CNAMERecords,
				ARecords:     dnsResult.ARecords,
			})
			continue
		}

		responses = append(responses, *response)
	}

	if len(responses) == 0 {
		return nil, fmt.Errorf("no successful responses from A records")
	}

	// Analyze header stability
	stableHeaders, differenceFound := c.findStableHeaders(responses)

	return &AnalysisResult{
		CNAMERecords:          dnsResult.CNAMERecords,
		ARecords:              dnsResult.ARecords,
		StableHeaders:         stableHeaders,
		DifferentHeadersFound: differenceFound,
		Responses:             responses,
	}, nil
}

// makeRequestWithTCPAnalysis makes an HTTP request and includes TCP analysis
func (c *Client) makeRequestWithTCPAnalysis(targetURL, hostHeader string, aRecord dns.Record, dnsResult *dns.Result) (*Response, error) {
	startTime := time.Now()

	// Make HTTP request
	_, tlsVersion, reqHeaders, respHeaders, err := c.makeHTTPRequest(targetURL, hostHeader)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}

	duration := time.Since(startTime)

	// Analyze headers
	headerAnalyzer := &HeaderAnalyzerImpl{}
	cdnInfo := headerAnalyzer.DetectCDNProvider(respHeaders)
	cdnDetections := headerAnalyzer.DetectCDNWithConfidence(respHeaders)
	serverInfo := headerAnalyzer.FingerprintServer(respHeaders)
	keepAliveTimeout := headerAnalyzer.ExtractKeepAliveTimeout(getHeaderValue(respHeaders, "Keep-Alive"))

	// TODO: Integrate TCP analysis and CSP generation here
	// For now, we'll set placeholder values
	tcpResults := "{\"placeholder\": \"tcp analysis not yet integrated\"}"
	cspDetails := "CSP analysis not yet integrated"

	return &Response{
		Domain:           aRecord.IP, // Use IP address for TCP/CSP analysis
		KeepAliveTimeout: keepAliveTimeout,
		RequestDuration:  duration.Milliseconds(), // Convert to milliseconds
		TLSVersion:       tlsVersion,
		ConnectionHeader: getHeaderValue(respHeaders, "Connection"),
		ServerHeader:     getHeaderValue(respHeaders, "Server"),
		PoweredByHeader:  getHeaderValue(respHeaders, "X-Powered-By"),
		ForwardedHeader:  getForwardedHeader(respHeaders),
		RealIPHeader:     getHeaderValue(respHeaders, "X-Real-IP"),
		XCacheHeader:     cdnInfo.XCache,
		CloudflareHeader: cdnInfo.Cloudflare,
		CloudFrontHeader: cdnInfo.CloudFront,
		AkamaiHeader:     cdnInfo.Akamai,
		CDNInfo:          cdnInfo,
		CDNDetections:    cdnDetections,
		ServerInfo:       serverInfo,
		CNAMERecords:     dnsResult.CNAMERecords,
		ARecords:         dnsResult.ARecords,
		TCPResults:       tcpResults,
		CSPDetails:       cspDetails,
		RequestHeaders:   reqHeaders,
		ResponseHeaders:  respHeaders,
	}, nil
}

// makeHTTPRequest performs the actual HTTP request
func (c *Client) makeHTTPRequest(targetURL, hostHeader string) (string, string, http.Header, http.Header, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return "", "", nil, nil, err
	}

	req.Host = hostHeader
	req.Header.Set("User-Agent", c.config.UserAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", nil, nil, err
	}
	defer resp.Body.Close()

	// Read response body to ensure connection is properly handled
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", "", nil, nil, err
	}

	tlsVersion := "Unknown"
	if resp.TLS != nil {
		tlsVersion = tlsVersionToString(resp.TLS.Version)
	}

	return resp.Request.URL.String(), tlsVersion, req.Header, resp.Header, nil
}

// MakeRequest is a simpler interface for making individual requests
func (c *Client) MakeRequest(url, hostHeader string) (*Response, error) {
	// This is a simplified version - in a real implementation,
	// you might want to resolve DNS separately
	return nil, fmt.Errorf("not implemented - use AnalyzeDomain instead")
}

// findStableHeaders identifies headers that are consistent across all responses
func (c *Client) findStableHeaders(responses []Response) (map[string]string, bool) {
	if len(responses) == 0 {
		return nil, false
	}

	differenceFound := false
	commonHeaders := make(map[string]string)

	// Use first response's headers as baseline
	baseHeaders := responses[0].ResponseHeaders

	for headerName, headerValues := range baseHeaders {
		allSame := true
		
		for i := 1; i < len(responses); i++ {
			otherValues, exists := responses[i].ResponseHeaders[headerName]
			if !exists || !stringSlicesEqual(headerValues, otherValues) {
				allSame = false
				break
			}
		}

		if allSame {
			commonHeaders[headerName] = strings.Join(headerValues, ", ")
		} else {
			differenceFound = true
		}
	}

	return commonHeaders, differenceFound
}

// Helper functions

func getHeaderValue(headers http.Header, key string) string {
	values := headers[key]
	if len(values) > 0 {
		return values[0]
	}
	return "Not Defined"
}

func getForwardedHeader(headers http.Header) string {
	if forwarded := getHeaderValue(headers, "X-Forwarded-For"); forwarded != "Not Defined" {
		return forwarded
	}
	return getHeaderValue(headers, "X-Real-IP")
}

func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return "Unknown"
	}
}

