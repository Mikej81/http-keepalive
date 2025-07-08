package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
)

const (
	defaultPublicDir = "public"
	defaultTemplateDir = "public"
)

// New creates a new handler instance
func New(service Service, config *Config) *Handler {
	if config == nil {
		config = &Config{
			PublicDir:   defaultPublicDir,
			TemplateDir: defaultTemplateDir,
		}
	}

	return &Handler{
		service: service,
		config:  config,
	}
}

// Home handles the home page requests
func (h *Handler) Home(w http.ResponseWriter, r *http.Request) {
	// Add security headers
	h.addSecurityHeaders(w)
	
	if r.URL.Path == "/" {
		h.renderTemplate(w, "index.html", nil)
		return
	}
	
	// Serve static files
	http.ServeFile(w, r, filepath.Join(h.config.PublicDir, r.URL.Path))
}

// Analyze handles domain analysis requests
func (h *Handler) Analyze(w http.ResponseWriter, r *http.Request) {
	log.Println("Analyze handler called")
	
	// Add security headers
	h.addSecurityHeaders(w)

	if r.Method != http.MethodPost {
		h.writeErrorResponse(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var req AnalyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate and normalize domain
	domain, err := h.normalizeDomain(req.Domain)
	if err != nil {
		h.writeErrorResponse(w, "Invalid domain URL", http.StatusBadRequest)
		return
	}

	log.Printf("Analyzing domain: %s, using cached DNS: %v", domain, req.UseCachedDNS)

	// Perform analysis
	result, err := h.service.AnalyzeDomain(domain, req.UseCachedDNS)
	if err != nil {
		log.Printf("Analysis failed: %v", err)
		h.writeErrorResponse(w, fmt.Sprintf("Analysis failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Return successful response
	w.Header().Set("Content-Type", "application/json")
	log.Printf("Analysis completed successfully")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Printf("Failed to encode response: %v", err)
	}
}

// AnalyzeAPI handles API-only domain analysis requests (supports both GET and POST)
func (h *Handler) AnalyzeAPI(w http.ResponseWriter, r *http.Request) {
	log.Printf("API analyze handler called: %s %s", r.Method, r.URL.Path)
	
	// Set JSON content type and CORS headers for API usage
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	
	// Handle preflight OPTIONS request
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	
	var req AnalyzeRequest
	var err error
	
	// Handle both GET and POST requests
	if r.Method == http.MethodGet {
		// Get parameters from query string
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			h.writeJSONError(w, "Missing 'domain' parameter", http.StatusBadRequest)
			return
		}
		
		useCachedDNS := r.URL.Query().Get("useCachedDns") == "true"
		req = AnalyzeRequest{
			Domain:       domain,
			UseCachedDNS: useCachedDNS,
		}
	} else if r.Method == http.MethodPost {
		// Parse JSON body
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.writeJSONError(w, "Invalid request body", http.StatusBadRequest)
			return
		}
	} else {
		h.writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate and normalize domain
	domain, err := h.normalizeDomain(req.Domain)
	if err != nil {
		h.writeJSONError(w, "Invalid domain URL", http.StatusBadRequest)
		return
	}

	log.Printf("API analyzing domain: %s, using cached DNS: %v", domain, req.UseCachedDNS)

	// Perform analysis
	result, err := h.service.AnalyzeDomain(domain, req.UseCachedDNS)
	if err != nil {
		log.Printf("API analysis failed: %v", err)
		h.writeJSONError(w, fmt.Sprintf("Analysis failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Return successful response
	log.Printf("API analysis completed successfully for domain: %s", domain)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Printf("Failed to encode API response: %v", err)
		h.writeJSONError(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// HealthCheck provides a simple health check endpoint
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	
	if r.Method != http.MethodGet {
		h.writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	response := map[string]interface{}{
		"status": "ok",
		"service": "HTTP Keep-Alive Analyzer",
		"version": "2.0",
		"endpoints": map[string]string{
			"analyze_post": "/api/analyze (POST with JSON body)",
			"analyze_get":  "/api/analyze?domain=example.com&useCachedDns=false",
			"health":       "/api/health",
		},
	}
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode health check response: %v", err)
	}
}

// writeJSONError writes a JSON error response
func (h *Handler) writeJSONError(w http.ResponseWriter, message string, statusCode int) {
	log.Printf("API error response: %s (status: %d)", message, statusCode)
	w.WriteHeader(statusCode)
	
	errorResponse := map[string]interface{}{
		"error": message,
		"status": statusCode,
	}
	
	if err := json.NewEncoder(w).Encode(errorResponse); err != nil {
		log.Printf("Failed to encode error response: %v", err)
	}
}

// renderTemplate renders an HTML template
func (h *Handler) renderTemplate(w http.ResponseWriter, templateName string, data interface{}) {
	templatePath := filepath.Join(h.config.TemplateDir, templateName)
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		log.Printf("Failed to parse template %s: %v", templateName, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Failed to execute template %s: %v", templateName, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// writeErrorResponse writes an error response
func (h *Handler) writeErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	log.Printf("Error response: %s (status: %d)", message, statusCode)
	http.Error(w, message, statusCode)
}

// normalizeDomain normalizes and validates domain URLs
func (h *Handler) normalizeDomain(domain string) (string, error) {
	// Add protocol if missing
	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		domain = "http://" + domain
	}

	// Parse and validate URL
	parsedURL, err := url.Parse(domain)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	// Ensure we have a valid hostname
	if parsedURL.Hostname() == "" {
		return "", fmt.Errorf("invalid hostname in URL")
	}

	return domain, nil
}

// addSecurityHeaders adds security headers to the response
func (h *Handler) addSecurityHeaders(w http.ResponseWriter) {
	// Content Security Policy
	csp := "default-src 'self'; " +
		"script-src 'self' https://cdn.jsdelivr.net; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; " +
		"font-src 'self'; " +
		"connect-src 'self'; " +
		"frame-ancestors 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'"
	
	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
}

// SetupRoutes sets up all HTTP routes
func (h *Handler) SetupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", h.Home)
	mux.HandleFunc("/analyze", h.Analyze)
	
	// API endpoints
	mux.HandleFunc("/api/analyze", h.AnalyzeAPI)
	mux.HandleFunc("/api/health", h.HealthCheck)
	
	// Static file server
	fs := http.FileServer(http.Dir(h.config.PublicDir))
	mux.Handle("/public/", http.StripPrefix("/public/", fs))
}