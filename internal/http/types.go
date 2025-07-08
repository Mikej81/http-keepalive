package http

import (
	"net/http"
	"time"

	"http-keepalive/internal/dns"
)

// Response represents the analysis result for a single HTTP request
type Response struct {
	Domain           string             `json:"domain"`
	KeepAliveTimeout string             `json:"keepAliveTimeout"`
	RequestDuration  int64              `json:"requestDuration"` // milliseconds
	TLSVersion       string             `json:"tlsVersion"`
	ConnectionHeader string             `json:"connectionHeader"`
	ServerHeader     string             `json:"serverHeader"`
	PoweredByHeader  string             `json:"poweredByHeader"`
	ForwardedHeader  string             `json:"forwardedHeader"`
	RealIPHeader     string             `json:"realIPHeader"`
	XCacheHeader     string             `json:"xCacheHeader"`
	CloudflareHeader string             `json:"cloudflareHeader"`
	CloudFrontHeader string             `json:"cloudFrontHeader"`
	AkamaiHeader     string             `json:"akamaiHeader"`
	CDNInfo          CDNInfo             `json:"cdnInfo"`
	CDNDetections    map[string]CDNDetection `json:"cdnDetections"`
	ServerInfo       ServerInfo          `json:"serverInfo"`
	CNAMERecords     []string           `json:"cnameRecords"`
	ARecords         []dns.Record       `json:"aRecords"`
	TCPResults       string             `json:"tcpResults"`
	CSPDetails       string             `json:"cspDetails"`
	RequestHeaders   http.Header        `json:"requestHeaders,omitempty"`
	ResponseHeaders  http.Header        `json:"responseHeaders,omitempty"`
	Error            string             `json:"error,omitempty"`
}

// AnalysisResult contains the aggregated results from multiple HTTP requests
type AnalysisResult struct {
	CNAMERecords          []string           `json:"cnameRecords"`
	ARecords              []dns.Record       `json:"aRecords"`
	StableHeaders         map[string]string  `json:"stableHeaders"`
	DifferentHeadersFound bool               `json:"differentHeadersFound"`
	Responses             []Response         `json:"responses"`
}

// Config holds HTTP client configuration
type Config struct {
	Timeout             time.Duration
	InsecureSkipVerify  bool
	MaxRedirects        int
	UserAgent           string
}

// Analyzer defines the interface for HTTP analysis
type Analyzer interface {
	AnalyzeDomain(domain string, dnsResult *dns.Result) (*AnalysisResult, error)
	MakeRequest(url, hostHeader string) (*Response, error)
}

// HeaderAnalyzer provides methods for analyzing HTTP headers
type HeaderAnalyzer interface {
	ExtractKeepAliveTimeout(header string) string
	DetectCDNProvider(headers http.Header) CDNInfo
	DetectCDNWithConfidence(headers http.Header) map[string]CDNDetection
	FindStableHeaders(responses []Response) (map[string]string, bool)
}

// CDNInfo contains information about detected CDN providers
type CDNInfo struct {
	Cloudflare string `json:"cloudflare"`
	CloudFront string `json:"cloudfront"`
	Akamai     string `json:"akamai"`
	Fastly     string `json:"fastly"`
	KeyCDN     string `json:"keycdn"`
	MaxCDN     string `json:"maxcdn"`
	Incapsula  string `json:"incapsula"`
	Sucuri     string `json:"sucuri"`
	XCache     string `json:"xcache"`
	Via        string `json:"via"`
}

// CDNDetection represents detailed CDN detection results with confidence
type CDNDetection struct {
	Provider     string   `json:"provider"`
	Detected     bool     `json:"detected"`
	Confidence   string   `json:"confidence"`   // High, Medium, Low
	Evidence     []string `json:"evidence"`     // List of detection reasons
	PrimaryEvidence string `json:"primaryEvidence"` // Main detection reason
}

// ServerInfo contains detailed server fingerprinting information
type ServerInfo struct {
	ServerType    string `json:"serverType"`    // nginx, apache, iis, etc.
	Version       string `json:"version"`       // version if detected
	Platform      string `json:"platform"`     // linux, windows, etc.
	PoweredBy     string `json:"poweredBy"`    // technology stack
	LoadBalancer  string `json:"loadBalancer"` // HAProxy, F5, etc.
	Confidence    string `json:"confidence"`   // high, medium, low
	Fingerprint   string `json:"fingerprint"`  // unique signature
}