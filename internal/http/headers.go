package http

import (
	"net/http"
	"strings"
)

// HeaderAnalyzerImpl implements the HeaderAnalyzer interface
type HeaderAnalyzerImpl struct{}

// ExtractKeepAliveTimeout extracts the timeout value from Keep-Alive header
func (h *HeaderAnalyzerImpl) ExtractKeepAliveTimeout(keepAliveHeader string) string {
	if strings.Contains(keepAliveHeader, "timeout=") {
		parts := strings.Split(keepAliveHeader, "=")
		if len(parts) > 1 {
			return strings.TrimSpace(parts[1])
		}
	}
	return "Not Defined"
}

// DetectCDNProvider detects various CDN providers from HTTP headers
func (h *HeaderAnalyzerImpl) DetectCDNProvider(headers http.Header) CDNInfo {
	info := CDNInfo{
		Cloudflare: "No",
		CloudFront: "No", 
		Akamai:     "No",
		Fastly:     "No",
		KeyCDN:     "No",
		MaxCDN:     "No",
		Incapsula:  "No",
		Sucuri:     "No",
		XCache:     "No",
		Via:        "No",
	}

	// Cloudflare Detection
	if cfRay := headers.Get("CF-Ray"); cfRay != "" {
		info.Cloudflare = "CF-Ray: " + cfRay
	} else if cfCacheStatus := headers.Get("CF-Cache-Status"); cfCacheStatus != "" {
		info.Cloudflare = "CF-Cache-Status: " + cfCacheStatus
	} else if cfConnectingIP := headers.Get("CF-Connecting-IP"); cfConnectingIP != "" {
		info.Cloudflare = "CF-Connecting-IP: " + cfConnectingIP
	} else if cfIPCountry := headers.Get("CF-IPCountry"); cfIPCountry != "" {
		info.Cloudflare = "CF-IPCountry: " + cfIPCountry
	} else if cfVisitor := headers.Get("CF-Visitor"); cfVisitor != "" {
		info.Cloudflare = "CF-Visitor: " + cfVisitor
	} else if server := headers.Get("Server"); strings.Contains(strings.ToLower(server), "cloudflare") {
		info.Cloudflare = "Server: " + server
	} else if expectCT := headers.Get("Expect-CT"); strings.Contains(strings.ToLower(expectCT), "cloudflare") {
		info.Cloudflare = "Expect-CT: " + expectCT
	}

	// CloudFront (AWS) Detection
	if cfRequestId := headers.Get("X-Amz-Cf-Id"); cfRequestId != "" {
		info.CloudFront = "X-Amz-Cf-Id: " + cfRequestId
	} else if via := headers.Get("Via"); strings.Contains(strings.ToLower(via), "cloudfront") {
		info.CloudFront = "Via: " + via
	} else if xCache := headers.Get("X-Cache"); strings.Contains(strings.ToLower(xCache), "cloudfront") {
		info.CloudFront = "X-Cache: " + xCache
	} else if server := headers.Get("Server"); strings.Contains(strings.ToLower(server), "cloudfront") {
		info.CloudFront = "Server: " + server
	} else {
		// Check for AWS Load Balancer cookies (often used with CloudFront)
		if cookies := headers["Set-Cookie"]; cookies != nil {
			for _, cookie := range cookies {
				if strings.Contains(cookie, "AWSALB") || strings.Contains(cookie, "AWSALBCORS") {
					info.CloudFront = "Cookie: AWSALB detected"
					break
				}
			}
		}
	}

	// Akamai Detection
	if akamaiInfo := h.detectAkamai(headers); akamaiInfo != "" {
		info.Akamai = akamaiInfo
	}

	// Fastly Detection  
	if fastlyInfo := h.detectFastly(headers); fastlyInfo != "" {
		info.Fastly = fastlyInfo
	}

	// KeyCDN Detection
	if keyCDNInfo := h.detectKeyCDN(headers); keyCDNInfo != "" {
		info.KeyCDN = keyCDNInfo
	}

	// MaxCDN Detection
	if maxCDNInfo := h.detectMaxCDN(headers); maxCDNInfo != "" {
		info.MaxCDN = maxCDNInfo
	}

	// Incapsula Detection
	if incapsulaInfo := h.detectIncapsula(headers); incapsulaInfo != "" {
		info.Incapsula = incapsulaInfo
	}

	// Sucuri Detection
	if sucuriInfo := h.detectSucuri(headers); sucuriInfo != "" {
		info.Sucuri = sucuriInfo
	}

	// Check for additional CDN providers in generic headers
	h.detectAdditionalCDNs(headers, &info)

	// Generic Cache Headers
	if xCache := headers.Get("X-Cache"); xCache != "" {
		info.XCache = xCache
	}

	// Via Header (proxy chain)
	if via := headers.Get("Via"); via != "" {
		info.Via = via
	}

	return info
}

// detectAkamai checks for various Akamai-specific headers
func (h *HeaderAnalyzerImpl) detectAkamai(headers http.Header) string {
	// Primary Akamai headers (most reliable)
	akamaiHeaders := map[string]string{
		"X-Akamai-Transformed":   "X-Akamai-Transformed",
		"X-Akamai-Session-Info":  "X-Akamai-Session-Info", 
		"Akamai-Origin-Hop":      "Akamai-Origin-Hop",
		"X-Akamai-Staging":       "X-Akamai-Staging",
		"X-Akamai-Edge-IP":       "X-Akamai-Edge-IP",
		"X-Akamai-Request-ID":    "X-Akamai-Request-ID",
		"X-Akamai-Config-Log-Detail": "X-Akamai-Config-Log-Detail",
	}

	for header, name := range akamaiHeaders {
		if value := headers.Get(header); value != "" {
			return name + ": " + value
		}
	}
	
	// Check True-Client-IP (common with Akamai)
	if trueClientIP := headers.Get("True-Client-IP"); trueClientIP != "" {
		return "True-Client-IP: " + trueClientIP
	}
	
	// Check Server header for Akamai signature
	if server := headers.Get("Server"); strings.Contains(strings.ToLower(server), "akamai") {
		return "Server: " + server
	}
	
	// Check X-Cache for Akamai patterns
	if xCache := headers.Get("X-Cache"); xCache != "" {
		xCacheLower := strings.ToLower(xCache)
		if strings.Contains(xCacheLower, "akamai") || 
		   (strings.Contains(xCacheLower, "tcp") && strings.Contains(xCacheLower, "hit")) {
			return "X-Cache: " + xCache
		}
	}
	
	return ""
}

// detectFastly checks for Fastly CDN headers
func (h *HeaderAnalyzerImpl) detectFastly(headers http.Header) string {
	// Check for Fastly-specific headers first (most reliable)
	fastlySpecificHeaders := []string{
		"Fastly-Debug-Path",
		"Fastly-Debug-TTL", 
		"Fastly-Debug-Digest",
		"X-Fastly-Request-ID",
		"X-Fastly-Trace",
		"Fastly-IO",
		"Fastly-Restarts",
	}
	
	for _, header := range fastlySpecificHeaders {
		if value := headers.Get(header); value != "" {
			return header + ": " + value
		}
	}

	// Check common headers with Fastly signatures
	if xServedBy := headers.Get("X-Served-By"); xServedBy != "" {
		// Fastly X-Served-By typically contains cache server names
		if strings.Contains(strings.ToLower(xServedBy), "cache-") || 
		   strings.Contains(strings.ToLower(xServedBy), "fastly") {
			return "X-Served-By: " + xServedBy
		}
	}

	// Check X-Cache for Fastly patterns
	if xCache := headers.Get("X-Cache"); xCache != "" {
		xCacheLower := strings.ToLower(xCache)
		if strings.Contains(xCacheLower, "hit") || 
		   strings.Contains(xCacheLower, "miss") || 
		   strings.Contains(xCacheLower, "fastly") {
			// Check if combined with other Fastly indicators
			if h.hasFastlyIndicators(headers) {
				return "X-Cache: " + xCache
			}
		}
	}

	// Check X-Timer (Fastly timing header)
	if xTimer := headers.Get("X-Timer"); xTimer != "" {
		// Fastly X-Timer has specific format
		if strings.Contains(xTimer, "S") && (strings.Contains(xTimer, ".") || strings.Contains(xTimer, ",")) {
			return "X-Timer: " + xTimer
		}
	}

	// Check Via header for Fastly
	if via := headers.Get("Via"); via != "" {
		viaLower := strings.ToLower(via)
		if strings.Contains(viaLower, "fastly") || 
		   strings.Contains(viaLower, "varnish") {
			return "Via: " + via
		}
	}

	// Check Age header combined with other indicators
	if age := headers.Get("Age"); age != "" {
		if h.hasFastlyIndicators(headers) {
			return "Age: " + age + " (with Fastly indicators)"
		}
	}

	return ""
}

// hasFastlyIndicators checks for common Fastly header combinations
func (h *HeaderAnalyzerImpl) hasFastlyIndicators(headers http.Header) bool {
	indicators := 0
	
	// Common Fastly header combinations
	if headers.Get("X-Served-By") != "" { indicators++ }
	if headers.Get("X-Cache") != "" { indicators++ }
	if headers.Get("X-Timer") != "" { indicators++ }
	if headers.Get("Age") != "" { indicators++ }
	if headers.Get("Via") != "" { indicators++ }
	
	// Additional headers often seen with Fastly
	if headers.Get("Cache-Control") != "" { indicators++ }
	if headers.Get("Vary") != "" { indicators++ }
	
	// Need at least 2 indicators for positive identification
	return indicators >= 2
}

// detectKeyCDN checks for KeyCDN headers
func (h *HeaderAnalyzerImpl) detectKeyCDN(headers http.Header) string {
	keyCDNHeaders := map[string]string{
		"X-Edge-Location": "X-Edge-Location",
		"X-Cache":         "X-Cache",
		"Server":          "Server",
	}

	for header, name := range keyCDNHeaders {
		if value := headers.Get(header); value != "" && strings.Contains(strings.ToLower(value), "keycdn") {
			return name + ": " + value
		}
	}

	return ""
}

// detectMaxCDN checks for MaxCDN headers
func (h *HeaderAnalyzerImpl) detectMaxCDN(headers http.Header) string {
	if xCache := headers.Get("X-Cache"); strings.Contains(strings.ToLower(xCache), "maxcdn") {
		return "X-Cache: " + xCache
	}
	
	if server := headers.Get("Server"); strings.Contains(strings.ToLower(server), "maxcdn") {
		return "Server: " + server
	}

	return ""
}

// detectIncapsula checks for Incapsula headers
func (h *HeaderAnalyzerImpl) detectIncapsula(headers http.Header) string {
	incapsulaHeaders := map[string]string{
		"X-Iinfo":    "X-Iinfo",
		"X-CDN":      "X-CDN", 
		"Set-Cookie": "visid_incap",
	}

	for header, identifier := range incapsulaHeaders {
		if values := headers[header]; values != nil {
			for _, value := range values {
				if strings.Contains(strings.ToLower(value), identifier) {
					return header + ": " + identifier + " detected"
				}
			}
		}
	}

	return ""
}

// detectSucuri checks for Sucuri headers
func (h *HeaderAnalyzerImpl) detectSucuri(headers http.Header) string {
	sucuriHeaders := map[string]string{
		"X-Sucuri-ID":    "X-Sucuri-ID",
		"X-Sucuri-Cache": "X-Sucuri-Cache",
		"Server":         "sucuri",
	}

	for header, identifier := range sucuriHeaders {
		if value := headers.Get(header); value != "" && strings.Contains(strings.ToLower(value), identifier) {
			return header + ": " + value
		}
	}

	return ""
}

// FingerprintServer performs comprehensive server fingerprinting
func (h *HeaderAnalyzerImpl) FingerprintServer(headers http.Header) ServerInfo {
	serverInfo := ServerInfo{
		ServerType:   "Unknown",
		Version:      "Unknown",
		Platform:     "Unknown", 
		PoweredBy:    "Unknown",
		LoadBalancer: "Unknown",
		Confidence:   "Low",
		Fingerprint:  "",
	}

	serverHeader := headers.Get("Server")
	poweredBy := headers.Get("X-Powered-By")
	
	// Analyze Server header
	if serverHeader != "" {
		serverInfo = h.analyzeServerHeader(serverHeader, serverInfo)
	}
	
	// Analyze X-Powered-By header
	if poweredBy != "" {
		serverInfo.PoweredBy = poweredBy
		serverInfo = h.analyzePoweredByHeader(poweredBy, serverInfo)
	}
	
	// Detect load balancers
	serverInfo = h.detectLoadBalancer(headers, serverInfo)
	
	// Generate fingerprint
	serverInfo.Fingerprint = h.generateFingerprint(headers)
	
	// Determine confidence based on available information
	serverInfo.Confidence = h.calculateConfidence(serverInfo, headers)

	return serverInfo
}

// analyzeServerHeader extracts information from Server header
func (h *HeaderAnalyzerImpl) analyzeServerHeader(server string, info ServerInfo) ServerInfo {
	serverLower := strings.ToLower(server)
	
	// nginx detection
	if strings.Contains(serverLower, "nginx") {
		info.ServerType = "nginx"
		info.Platform = "Linux/Unix"
		if version := h.extractVersion(server, "nginx"); version != "" {
			info.Version = version
		}
	}
	
	// Apache detection  
	if strings.Contains(serverLower, "apache") {
		info.ServerType = "Apache"
		if strings.Contains(serverLower, "win") {
			info.Platform = "Windows"
		} else {
			info.Platform = "Linux/Unix"
		}
		if version := h.extractVersion(server, "apache"); version != "" {
			info.Version = version
		}
	}
	
	// IIS detection
	if strings.Contains(serverLower, "iis") || strings.Contains(serverLower, "microsoft") {
		info.ServerType = "IIS"
		info.Platform = "Windows"
		if version := h.extractVersion(server, "iis"); version != "" {
			info.Version = version
		}
	}
	
	// LiteSpeed detection
	if strings.Contains(serverLower, "litespeed") {
		info.ServerType = "LiteSpeed"
		info.Platform = "Linux/Unix"
		if version := h.extractVersion(server, "litespeed"); version != "" {
			info.Version = version
		}
	}
	
	// Other servers
	if strings.Contains(serverLower, "openresty") {
		info.ServerType = "OpenResty"
		info.Platform = "Linux/Unix"
	}
	
	if strings.Contains(serverLower, "caddy") {
		info.ServerType = "Caddy"
		info.Platform = "Cross-platform"
	}

	return info
}

// analyzePoweredByHeader extracts technology stack information
func (h *HeaderAnalyzerImpl) analyzePoweredByHeader(poweredBy string, info ServerInfo) ServerInfo {
	poweredByLower := strings.ToLower(poweredBy)
	
	// Update platform based on technology
	if strings.Contains(poweredByLower, "asp.net") {
		info.Platform = "Windows"
		if info.ServerType == "Unknown" {
			info.ServerType = "IIS"
		}
	}
	
	if strings.Contains(poweredByLower, "php") {
		if info.Platform == "Unknown" {
			info.Platform = "Linux/Unix"
		}
	}
	
	return info
}

// detectLoadBalancer identifies load balancers from headers
func (h *HeaderAnalyzerImpl) detectLoadBalancer(headers http.Header, info ServerInfo) ServerInfo {
	// HAProxy detection
	if server := headers.Get("Server"); strings.Contains(strings.ToLower(server), "haproxy") {
		info.LoadBalancer = "HAProxy"
	}
	
	// F5 BIG-IP detection
	if bigipServer := headers.Get("X-WA-Info"); bigipServer != "" {
		info.LoadBalancer = "F5 BIG-IP"
	}
	
	// AWS ALB detection
	if headers.Get("X-Amzn-Trace-Id") != "" {
		info.LoadBalancer = "AWS Application Load Balancer"
	}
	
	// Cloudflare as load balancer
	if headers.Get("CF-Ray") != "" {
		info.LoadBalancer = "Cloudflare"
	}

	return info
}

// extractVersion extracts version number from server string
func (h *HeaderAnalyzerImpl) extractVersion(server, serverType string) string {
	serverLower := strings.ToLower(server)
	typeIndex := strings.Index(serverLower, strings.ToLower(serverType))
	
	if typeIndex == -1 {
		return ""
	}
	
	// Look for version pattern after server type
	versionStart := typeIndex + len(serverType)
	if versionStart >= len(server) {
		return ""
	}
	
	// Find version pattern (digits and dots)
	versionStr := ""
	inVersion := false
	
	for i := versionStart; i < len(server); i++ {
		char := server[i]
		if char >= '0' && char <= '9' || char == '.' {
			inVersion = true
			versionStr += string(char)
		} else if inVersion {
			break
		} else if char == '/' || char == '-' {
			// Skip separators before version
			continue
		} else if char == ' ' && !inVersion {
			// Skip spaces before version
			continue
		} else if inVersion {
			break
		}
	}
	
	return versionStr
}

// generateFingerprint creates a unique fingerprint for the server
func (h *HeaderAnalyzerImpl) generateFingerprint(headers http.Header) string {
	fingerprint := ""
	
	importantHeaders := []string{
		"Server", "X-Powered-By", "X-AspNet-Version", 
		"X-Frame-Options", "X-Content-Type-Options",
		"Strict-Transport-Security", "Content-Security-Policy",
	}
	
	for _, header := range importantHeaders {
		if value := headers.Get(header); value != "" {
			fingerprint += header + ":" + value + ";"
		}
	}
	
	return fingerprint
}

// calculateConfidence determines confidence level of fingerprinting
func (h *HeaderAnalyzerImpl) calculateConfidence(info ServerInfo, headers http.Header) string {
	score := 0
	
	if info.ServerType != "Unknown" {
		score += 30
	}
	if info.Version != "Unknown" && info.Version != "" {
		score += 25
	}
	if info.Platform != "Unknown" {
		score += 20
	}
	if info.PoweredBy != "Unknown" && info.PoweredBy != "" {
		score += 15
	}
	if info.LoadBalancer != "Unknown" {
		score += 10
	}
	
	if score >= 70 {
		return "High"
	} else if score >= 40 {
		return "Medium"
	} else {
		return "Low"
	}
}

// FindStableHeaders identifies headers that are consistent across all responses
func (h *HeaderAnalyzerImpl) FindStableHeaders(responses []Response) (map[string]string, bool) {
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

// detectAdditionalCDNs checks for CDN patterns in common headers
func (h *HeaderAnalyzerImpl) detectAdditionalCDNs(headers http.Header, info *CDNInfo) {
	// Check Server header for various CDN signatures
	if server := headers.Get("Server"); server != "" {
		serverLower := strings.ToLower(server)
		
		// Check for various CDN servers
		if strings.Contains(serverLower, "varnish") && info.Fastly == "No" {
			info.Fastly = "Server: " + server + " (Varnish/Fastly)"
		}
		if strings.Contains(serverLower, "nginx") && strings.Contains(serverLower, "keycdn") && info.KeyCDN == "No" {
			info.KeyCDN = "Server: " + server
		}
		if strings.Contains(serverLower, "bunnycdn") && info.MaxCDN == "No" {
			info.MaxCDN = "Server: " + server + " (BunnyCDN)"
		}
	}
	
	// Check X-Cache for CDN patterns
	if xCache := headers.Get("X-Cache"); xCache != "" && info.Fastly == "No" {
		xCacheLower := strings.ToLower(xCache)
		
		// Enhanced cache status detection
		if (strings.Contains(xCacheLower, "hit") || strings.Contains(xCacheLower, "miss")) {
			// Look for additional Fastly indicators
			if h.hasCommonCDNHeaders(headers) {
				info.Fastly = "X-Cache: " + xCache + " (CDN detected)"
			}
		}
	}
	
	// Check for edge location headers
	if popHeader := headers.Get("X-Served-By"); popHeader != "" && info.Fastly == "No" {
		// Fastly edge servers often have specific naming patterns
		popLower := strings.ToLower(popHeader)
		if strings.Contains(popLower, "cache") || 
		   strings.Contains(popLower, "edge") ||
		   strings.Contains(popLower, "pop") {
			info.Fastly = "X-Served-By: " + popHeader
		}
	}
}

// hasCommonCDNHeaders checks for headers commonly associated with CDNs
func (h *HeaderAnalyzerImpl) hasCommonCDNHeaders(headers http.Header) bool {
	cdnHeaders := []string{
		"Age",
		"Cache-Control", 
		"Vary",
		"ETag",
		"Last-Modified",
		"X-Served-By",
		"X-Timer",
		"Via",
	}
	
	count := 0
	for _, header := range cdnHeaders {
		if headers.Get(header) != "" {
			count++
		}
	}
	
	// Need at least 3 common CDN headers for positive identification
	return count >= 3
}

// DetectCDNWithConfidence provides detailed CDN detection with confidence levels and evidence
func (h *HeaderAnalyzerImpl) DetectCDNWithConfidence(headers http.Header) map[string]CDNDetection {
	results := make(map[string]CDNDetection)
	
	// Detect each CDN provider with detailed analysis
	results["cloudflare"] = h.detectCloudflareWithConfidence(headers)
	results["cloudfront"] = h.detectCloudFrontWithConfidence(headers)
	results["akamai"] = h.detectAkamaiWithConfidence(headers)
	results["fastly"] = h.detectFastlyWithConfidence(headers)
	results["keycdn"] = h.detectKeyCDNWithConfidence(headers)
	results["maxcdn"] = h.detectMaxCDNWithConfidence(headers)
	results["incapsula"] = h.detectIncapsulaWithConfidence(headers)
	results["sucuri"] = h.detectSucuriWithConfidence(headers)
	
	return results
}

// detectCloudflareWithConfidence detects Cloudflare CDN with confidence analysis
func (h *HeaderAnalyzerImpl) detectCloudflareWithConfidence(headers http.Header) CDNDetection {
	detection := CDNDetection{
		Provider: "Cloudflare",
		Detected: false,
		Confidence: "Low",
		Evidence: []string{},
	}
	
	// High confidence indicators
	if cfRay := headers.Get("CF-Ray"); cfRay != "" {
		detection.Detected = true
		detection.Confidence = "High"
		detection.Evidence = append(detection.Evidence, "CF-Ray header present")
		detection.PrimaryEvidence = "CF-Ray: " + cfRay
		return detection
	}
	
	if cfCacheStatus := headers.Get("CF-Cache-Status"); cfCacheStatus != "" {
		detection.Detected = true
		detection.Confidence = "High"
		detection.Evidence = append(detection.Evidence, "CF-Cache-Status header present")
		detection.PrimaryEvidence = "CF-Cache-Status: " + cfCacheStatus
		return detection
	}
	
	// Medium confidence indicators
	if cfConnectingIP := headers.Get("CF-Connecting-IP"); cfConnectingIP != "" {
		detection.Detected = true
		detection.Confidence = "Medium"
		detection.Evidence = append(detection.Evidence, "CF-Connecting-IP header present")
		detection.PrimaryEvidence = "CF-Connecting-IP: " + cfConnectingIP
	}
	
	if cfIPCountry := headers.Get("CF-IPCountry"); cfIPCountry != "" {
		detection.Detected = true
		detection.Confidence = "Medium"
		detection.Evidence = append(detection.Evidence, "CF-IPCountry header present")
		if detection.PrimaryEvidence == "" {
			detection.PrimaryEvidence = "CF-IPCountry: " + cfIPCountry
		}
	}
	
	// Lower confidence indicators
	if server := headers.Get("Server"); strings.Contains(strings.ToLower(server), "cloudflare") {
		detection.Detected = true
		if detection.Confidence == "Low" {
			detection.Confidence = "Medium"
		}
		detection.Evidence = append(detection.Evidence, "Server header contains 'cloudflare'")
		if detection.PrimaryEvidence == "" {
			detection.PrimaryEvidence = "Server: " + server
		}
	}
	
	return detection
}

// detectCloudFrontWithConfidence detects CloudFront CDN with confidence analysis
func (h *HeaderAnalyzerImpl) detectCloudFrontWithConfidence(headers http.Header) CDNDetection {
	detection := CDNDetection{
		Provider: "CloudFront",
		Detected: false,
		Confidence: "Low",
		Evidence: []string{},
	}
	
	// High confidence indicators
	if cfRequestId := headers.Get("X-Amz-Cf-Id"); cfRequestId != "" {
		detection.Detected = true
		detection.Confidence = "High"
		detection.Evidence = append(detection.Evidence, "X-Amz-Cf-Id header present")
		detection.PrimaryEvidence = "X-Amz-Cf-Id: " + cfRequestId
		return detection
	}
	
	// Medium confidence indicators
	if via := headers.Get("Via"); strings.Contains(strings.ToLower(via), "cloudfront") {
		detection.Detected = true
		detection.Confidence = "Medium"
		detection.Evidence = append(detection.Evidence, "Via header contains 'cloudfront'")
		detection.PrimaryEvidence = "Via: " + via
	}
	
	if xCache := headers.Get("X-Cache"); strings.Contains(strings.ToLower(xCache), "cloudfront") {
		detection.Detected = true
		detection.Confidence = "Medium"
		detection.Evidence = append(detection.Evidence, "X-Cache header contains 'cloudfront'")
		if detection.PrimaryEvidence == "" {
			detection.PrimaryEvidence = "X-Cache: " + xCache
		}
	}
	
	// Lower confidence indicators
	if cookies := headers["Set-Cookie"]; cookies != nil {
		for _, cookie := range cookies {
			if strings.Contains(cookie, "AWSALB") || strings.Contains(cookie, "AWSALBCORS") {
				detection.Detected = true
				if detection.Confidence == "Low" {
					detection.Confidence = "Medium"
				}
				detection.Evidence = append(detection.Evidence, "AWS Load Balancer cookie present")
				if detection.PrimaryEvidence == "" {
					detection.PrimaryEvidence = "AWS ALB Cookie detected"
				}
				break
			}
		}
	}
	
	return detection
}

// detectAkamaiWithConfidence detects Akamai CDN with confidence analysis
func (h *HeaderAnalyzerImpl) detectAkamaiWithConfidence(headers http.Header) CDNDetection {
	detection := CDNDetection{
		Provider: "Akamai",
		Detected: false,
		Confidence: "Low",
		Evidence: []string{},
	}
	
	// High confidence indicators
	akamaiHeaders := map[string]string{
		"X-Akamai-Transformed":      "X-Akamai-Transformed header",
		"X-Akamai-Session-Info":     "X-Akamai-Session-Info header",
		"Akamai-Origin-Hop":         "Akamai-Origin-Hop header",
		"X-Akamai-Staging":          "X-Akamai-Staging header",
		"X-Akamai-Edge-IP":          "X-Akamai-Edge-IP header",
		"X-Akamai-Request-ID":       "X-Akamai-Request-ID header",
		"X-Akamai-Config-Log-Detail": "X-Akamai-Config-Log-Detail header",
	}
	
	for header, description := range akamaiHeaders {
		if value := headers.Get(header); value != "" {
			detection.Detected = true
			detection.Confidence = "High"
			detection.Evidence = append(detection.Evidence, description + " present")
			detection.PrimaryEvidence = header + ": " + value
			return detection
		}
	}
	
	// Medium confidence indicators
	if trueClientIP := headers.Get("True-Client-IP"); trueClientIP != "" {
		detection.Detected = true
		detection.Confidence = "Medium"
		detection.Evidence = append(detection.Evidence, "True-Client-IP header present")
		detection.PrimaryEvidence = "True-Client-IP: " + trueClientIP
	}
	
	// Lower confidence indicators
	if server := headers.Get("Server"); strings.Contains(strings.ToLower(server), "akamai") {
		detection.Detected = true
		if detection.Confidence == "Low" {
			detection.Confidence = "Medium"
		}
		detection.Evidence = append(detection.Evidence, "Server header contains 'akamai'")
		if detection.PrimaryEvidence == "" {
			detection.PrimaryEvidence = "Server: " + server
		}
	}
	
	return detection
}

// detectFastlyWithConfidence detects Fastly CDN with confidence analysis
func (h *HeaderAnalyzerImpl) detectFastlyWithConfidence(headers http.Header) CDNDetection {
	detection := CDNDetection{
		Provider: "Fastly",
		Detected: false,
		Confidence: "Low",
		Evidence: []string{},
	}
	
	// High confidence indicators (Fastly-specific headers)
	fastlyHeaders := []string{
		"Fastly-Debug-Path", "Fastly-Debug-TTL", "Fastly-Debug-Digest",
		"X-Fastly-Request-ID", "X-Fastly-Trace", "Fastly-IO", "Fastly-Restarts",
	}
	
	for _, header := range fastlyHeaders {
		if value := headers.Get(header); value != "" {
			detection.Detected = true
			detection.Confidence = "High"
			detection.Evidence = append(detection.Evidence, header + " header present")
			detection.PrimaryEvidence = header + ": " + value
			return detection
		}
	}
	
	// Medium confidence indicators
	if xServedBy := headers.Get("X-Served-By"); xServedBy != "" {
		if strings.Contains(strings.ToLower(xServedBy), "cache-") || strings.Contains(strings.ToLower(xServedBy), "fastly") {
			detection.Detected = true
			detection.Confidence = "Medium"
			detection.Evidence = append(detection.Evidence, "X-Served-By header with cache server pattern")
			detection.PrimaryEvidence = "X-Served-By: " + xServedBy
		}
	}
	
	if xTimer := headers.Get("X-Timer"); xTimer != "" {
		if strings.Contains(xTimer, "S") && (strings.Contains(xTimer, ".") || strings.Contains(xTimer, ",")) {
			detection.Detected = true
			detection.Confidence = "Medium"
			detection.Evidence = append(detection.Evidence, "X-Timer header with Fastly format")
			if detection.PrimaryEvidence == "" {
				detection.PrimaryEvidence = "X-Timer: " + xTimer
			}
		}
	}
	
	if via := headers.Get("Via"); via != "" {
		viaLower := strings.ToLower(via)
		if strings.Contains(viaLower, "fastly") {
			detection.Detected = true
			detection.Confidence = "Medium"
			detection.Evidence = append(detection.Evidence, "Via header contains 'fastly'")
			if detection.PrimaryEvidence == "" {
				detection.PrimaryEvidence = "Via: " + via
			}
		} else if strings.Contains(viaLower, "varnish") {
			detection.Detected = true
			detection.Confidence = "Medium"
			detection.Evidence = append(detection.Evidence, "Via header contains 'varnish' (Fastly backend)")
			if detection.PrimaryEvidence == "" {
				detection.PrimaryEvidence = "Via: " + via
			}
		}
	}
	
	// Lower confidence indicators - require correlation
	if xCache := headers.Get("X-Cache"); xCache != "" {
		xCacheLower := strings.ToLower(xCache)
		if (strings.Contains(xCacheLower, "hit") || strings.Contains(xCacheLower, "miss")) && h.hasFastlyIndicators(headers) {
			detection.Detected = true
			if detection.Confidence == "Low" {
				detection.Confidence = "Medium"
			}
			detection.Evidence = append(detection.Evidence, "X-Cache header with hit/miss pattern and Fastly indicators")
			if detection.PrimaryEvidence == "" {
				detection.PrimaryEvidence = "X-Cache: " + xCache
			}
		}
	}
	
	return detection
}

// detectKeyCDNWithConfidence detects KeyCDN with confidence analysis
func (h *HeaderAnalyzerImpl) detectKeyCDNWithConfidence(headers http.Header) CDNDetection {
	detection := CDNDetection{
		Provider: "KeyCDN",
		Detected: false,
		Confidence: "Low",
		Evidence: []string{},
	}
	
	keyCDNHeaders := []string{"X-Edge-Location", "X-Cache", "Server"}
	
	for _, header := range keyCDNHeaders {
		if value := headers.Get(header); value != "" && strings.Contains(strings.ToLower(value), "keycdn") {
			detection.Detected = true
			detection.Confidence = "High"
			detection.Evidence = append(detection.Evidence, header + " header contains 'keycdn'")
			detection.PrimaryEvidence = header + ": " + value
			return detection
		}
	}
	
	return detection
}

// detectMaxCDNWithConfidence detects MaxCDN with confidence analysis
func (h *HeaderAnalyzerImpl) detectMaxCDNWithConfidence(headers http.Header) CDNDetection {
	detection := CDNDetection{
		Provider: "MaxCDN",
		Detected: false,
		Confidence: "Low",
		Evidence: []string{},
	}
	
	if xCache := headers.Get("X-Cache"); strings.Contains(strings.ToLower(xCache), "maxcdn") {
		detection.Detected = true
		detection.Confidence = "High"
		detection.Evidence = append(detection.Evidence, "X-Cache header contains 'maxcdn'")
		detection.PrimaryEvidence = "X-Cache: " + xCache
	}
	
	if server := headers.Get("Server"); strings.Contains(strings.ToLower(server), "maxcdn") {
		detection.Detected = true
		detection.Confidence = "High"
		detection.Evidence = append(detection.Evidence, "Server header contains 'maxcdn'")
		if detection.PrimaryEvidence == "" {
			detection.PrimaryEvidence = "Server: " + server
		}
	}
	
	return detection
}

// detectIncapsulaWithConfidence detects Incapsula with confidence analysis
func (h *HeaderAnalyzerImpl) detectIncapsulaWithConfidence(headers http.Header) CDNDetection {
	detection := CDNDetection{
		Provider: "Incapsula",
		Detected: false,
		Confidence: "Low",
		Evidence: []string{},
	}
	
	if xIinfo := headers.Get("X-Iinfo"); xIinfo != "" {
		detection.Detected = true
		detection.Confidence = "High"
		detection.Evidence = append(detection.Evidence, "X-Iinfo header present")
		detection.PrimaryEvidence = "X-Iinfo: " + xIinfo
	}
	
	if xCDN := headers.Get("X-CDN"); strings.Contains(strings.ToLower(xCDN), "incapsula") {
		detection.Detected = true
		detection.Confidence = "High"
		detection.Evidence = append(detection.Evidence, "X-CDN header contains 'incapsula'")
		if detection.PrimaryEvidence == "" {
			detection.PrimaryEvidence = "X-CDN: " + xCDN
		}
	}
	
	if cookies := headers["Set-Cookie"]; cookies != nil {
		for _, cookie := range cookies {
			if strings.Contains(strings.ToLower(cookie), "visid_incap") {
				detection.Detected = true
				detection.Confidence = "High"
				detection.Evidence = append(detection.Evidence, "Incapsula visitor ID cookie present")
				if detection.PrimaryEvidence == "" {
					detection.PrimaryEvidence = "Incapsula cookie detected"
				}
				break
			}
		}
	}
	
	return detection
}

// detectSucuriWithConfidence detects Sucuri with confidence analysis
func (h *HeaderAnalyzerImpl) detectSucuriWithConfidence(headers http.Header) CDNDetection {
	detection := CDNDetection{
		Provider: "Sucuri",
		Detected: false,
		Confidence: "Low",
		Evidence: []string{},
	}
	
	if sucuriID := headers.Get("X-Sucuri-ID"); sucuriID != "" {
		detection.Detected = true
		detection.Confidence = "High"
		detection.Evidence = append(detection.Evidence, "X-Sucuri-ID header present")
		detection.PrimaryEvidence = "X-Sucuri-ID: " + sucuriID
	}
	
	if sucuriCache := headers.Get("X-Sucuri-Cache"); sucuriCache != "" {
		detection.Detected = true
		detection.Confidence = "High"
		detection.Evidence = append(detection.Evidence, "X-Sucuri-Cache header present")
		if detection.PrimaryEvidence == "" {
			detection.PrimaryEvidence = "X-Sucuri-Cache: " + sucuriCache
		}
	}
	
	if server := headers.Get("Server"); strings.Contains(strings.ToLower(server), "sucuri") {
		detection.Detected = true
		detection.Confidence = "High"
		detection.Evidence = append(detection.Evidence, "Server header contains 'sucuri'")
		if detection.PrimaryEvidence == "" {
			detection.PrimaryEvidence = "Server: " + server
		}
	}
	
	return detection
}

// Helper function to compare string slices
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}