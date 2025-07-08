package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"http-keepalive/internal/csp"
	"http-keepalive/internal/dns"
	httpAnalyzer "http-keepalive/internal/http"
	"http-keepalive/internal/tcp"
)

// AnalysisService implements the Service interface
type AnalysisService struct {
	dnsResolver  dns.Resolver
	httpAnalyzer httpAnalyzer.Analyzer
	tcpAnalyzer  tcp.Analyzer
	cspEvaluator csp.CSPEvaluator
	dnsConfig    *dns.Config
}

// NewAnalysisService creates a new analysis service
func NewAnalysisService(deps *Dependencies, dnsConfig *dns.Config) *AnalysisService {
	return &AnalysisService{
		dnsResolver:  deps.DNSResolver,
		httpAnalyzer: deps.HTTPAnalyzer,
		tcpAnalyzer:  deps.TCPAnalyzer,
		cspEvaluator: deps.CSPEvaluator,
		dnsConfig:    dnsConfig,
	}
}

// AnalyzeDomain performs comprehensive domain analysis
func (s *AnalysisService) AnalyzeDomain(domain string, useCachedDNS bool) (*httpAnalyzer.AnalysisResult, error) {
	log.Printf("Starting domain analysis for: %s", domain)

	// Parse the domain URL
	parsedURL, err := url.Parse(domain)
	if err != nil {
		return nil, fmt.Errorf("invalid domain URL: %w", err)
	}

	hostname := parsedURL.Hostname()
	
	// Create DNS resolver with updated configuration
	dnsConfig := &dns.Config{
		UseCachedDNS: useCachedDNS,
		DNSServer:    s.dnsConfig.DNSServer,
		Timeout:      s.dnsConfig.Timeout,
	}
	
	// Create a new resolver with the correct configuration
	resolver := dns.NewResolver(dnsConfig)

	// Resolve DNS records
	log.Printf("Resolving DNS records for: %s", hostname)
	dnsResult, err := resolver.ResolveDomain(hostname)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed: %w", err)
	}

	if len(dnsResult.ARecords) == 0 {
		return nil, fmt.Errorf("no A records found for domain")
	}

	log.Printf("Found %d A records for domain", len(dnsResult.ARecords))

	// Perform HTTP analysis
	result, err := s.httpAnalyzer.AnalyzeDomain(domain, dnsResult)
	if err != nil {
		return nil, fmt.Errorf("HTTP analysis failed: %w", err)
	}

	// Enhance each response with TCP analysis and CSP generation
	for i := range result.Responses {
		response := &result.Responses[i]
		
		// Add TCP analysis
		if response.Error == "" {
			s.enhanceWithTCPAnalysis(response, parsedURL)
		}

		// Add CSP analysis
		if response.Error == "" {
			s.enhanceWithCSPAnalysis(response, domain, hostname)
		}
	}

	log.Printf("Domain analysis completed successfully")
	return result, nil
}

// enhanceWithTCPAnalysis adds TCP analysis to the response
func (s *AnalysisService) enhanceWithTCPAnalysis(response *httpAnalyzer.Response, parsedURL *url.URL) {
	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	// response.Domain now contains just the IP address
	target := fmt.Sprintf("%s:%s", response.Domain, port)
	
	tcpResult, err := s.tcpAnalyzer.AnalyzeHandshake(target)
	if err != nil {
		log.Printf("TCP analysis failed for %s: %v", target, err)
		response.TCPResults = fmt.Sprintf(`{"error": "%s"}`, err.Error())
		return
	}

	// Convert TCP result to JSON
	tcpJSON, err := json.MarshalIndent(tcpResult, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal TCP results: %v", err)
		response.TCPResults = fmt.Sprintf(`{"error": "failed to marshal TCP results"}`)
		return
	}

	response.TCPResults = string(tcpJSON)
}

// enhanceWithCSPAnalysis adds CSP analysis to the response
func (s *AnalysisService) enhanceWithCSPAnalysis(response *httpAnalyzer.Response, originalDomain, hostname string) {
	// Use the original domain for CSP analysis to avoid TLS certificate issues
	// Don't replace hostname with IP address for CSP analysis
	
	// Simulate an HTTP response for CSP evaluation
	fakeResp := &http.Response{
		Header: response.ResponseHeaders,
	}
	
	cspComparison, err := s.cspEvaluator.EvaluateCSP(originalDomain, fakeResp)
	if err != nil {
		log.Printf("CSP evaluation failed for %s: %v", originalDomain, err)
		response.CSPDetails = fmt.Sprintf("Error evaluating CSP: %v", err)
		return
	}

	// Format CSP analysis results
	cspResult := s.formatCSPResults(cspComparison)
	response.CSPDetails = cspResult
}

// formatCSPResults formats CSP comparison results for display
func (s *AnalysisService) formatCSPResults(comparison *csp.CSPComparison) string {
	var result strings.Builder
	
	if comparison.ExistingPolicy != nil {
		result.WriteString("=== EXISTING CSP ANALYSIS ===\n")
		result.WriteString(fmt.Sprintf("Security Score: %d/100\n\n", comparison.SecurityScore))
		
		if len(comparison.Validation.Issues) > 0 {
			result.WriteString("SECURITY ISSUES:\n")
			for _, issue := range comparison.Validation.Issues {
				result.WriteString(fmt.Sprintf("- [%s] %s: %s\n", strings.ToUpper(issue.Severity), issue.Directive, issue.Message))
				result.WriteString(fmt.Sprintf("  Recommendation: %s\n", issue.Recommendation))
			}
			result.WriteString("\n")
		}
		
		if len(comparison.Validation.Warnings) > 0 {
			result.WriteString("WARNINGS:\n")
			for _, warning := range comparison.Validation.Warnings {
				result.WriteString(fmt.Sprintf("- %s: %s\n", warning.Directive, warning.Message))
				result.WriteString(fmt.Sprintf("  Recommendation: %s\n", warning.Recommendation))
			}
			result.WriteString("\n")
		}
		
		if len(comparison.Improvements) > 0 {
			result.WriteString("RECOMMENDED IMPROVEMENTS:\n")
			for _, improvement := range comparison.Improvements {
				result.WriteString(fmt.Sprintf("- %s %s: %s\n", strings.ToUpper(improvement.Type), improvement.Directive, improvement.Reason))
				if improvement.RecommendedValue != "" {
					result.WriteString(fmt.Sprintf("  Suggested: %s\n", improvement.RecommendedValue))
				}
			}
			result.WriteString("\n")
		}
	} else {
		result.WriteString("=== NO CSP HEADER FOUND ===\n")
		result.WriteString("Security Score: 0/100 - No Content Security Policy detected\n\n")
	}
	
	result.WriteString("=== RECOMMENDED OPTIMAL CSP ===\n")
	if comparison.OptimalPolicy != nil {
		optimalCSP := s.buildCSPString(comparison.OptimalPolicy)
		result.WriteString(optimalCSP)
		result.WriteString("\n\n")
		
		result.WriteString("This CSP provides:\n")
		result.WriteString("- Prevents XSS attacks through script-src restrictions\n")
		result.WriteString("- Blocks clickjacking with frame-ancestors 'none'\n")
		result.WriteString("- Prevents base tag injection with base-uri 'self'\n")
		result.WriteString("- Restricts form submissions with form-action 'self'\n")
		result.WriteString("- Blocks dangerous plugins with object-src 'none'\n")
	}
	
	return result.String()
}

// buildCSPString builds a CSP string from policy (helper method)
func (s *AnalysisService) buildCSPString(policy *csp.Policy) string {
	var builder strings.Builder
	
	directives := []struct {
		name    string
		sources []string
	}{
		{"default-src", policy.DefaultSrc},
		{"script-src", policy.ScriptSrc},
		{"style-src", policy.StyleSrc},
		{"img-src", policy.ImgSrc},
		{"font-src", policy.FontSrc},
		{"media-src", policy.MediaSrc},
		{"connect-src", policy.ConnectSrc},
		{"object-src", policy.ObjectSrc},
		{"frame-src", policy.FrameSrc},
		{"child-src", policy.ChildSrc},
		{"worker-src", policy.WorkerSrc},
		{"manifest-src", policy.ManifestSrc},
		{"frame-ancestors", policy.FrameAncestors},
		{"base-uri", policy.BaseURI},
		{"form-action", policy.FormAction},
	}

	for _, directive := range directives {
		if len(directive.sources) > 0 {
			builder.WriteString(directive.name)
			for _, source := range directive.sources {
				builder.WriteString(" ")
				builder.WriteString(source)
			}
			builder.WriteString("; ")
		}
	}

	result := builder.String()
	if len(result) > 2 {
		result = result[:len(result)-2]
	}

	return result
}

// tryHTTPSFallback attempts HTTPS if HTTP fails
func (s *AnalysisService) tryHTTPSFallback(domain string, dnsResult *dns.Result) (*httpAnalyzer.AnalysisResult, error) {
	parsedURL, err := url.Parse(domain)
	if err != nil {
		return nil, err
	}

	// Only try HTTPS fallback if we were using HTTP on port 80
	if parsedURL.Scheme == "http" && (parsedURL.Port() == "" || parsedURL.Port() == "80") {
		httpsURL := "https://" + parsedURL.Hostname()
		log.Printf("Trying HTTPS fallback: %s", httpsURL)
		
		return s.httpAnalyzer.AnalyzeDomain(httpsURL, dnsResult)
	}

	return nil, fmt.Errorf("no HTTPS fallback available")
}