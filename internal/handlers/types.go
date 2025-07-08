package handlers

import (
	"time"

	"http-keepalive/internal/csp"
	"http-keepalive/internal/dns"
	httpAnalyzer "http-keepalive/internal/http"
	"http-keepalive/internal/tcp"
)

// AnalyzeRequest represents the request payload for domain analysis
type AnalyzeRequest struct {
	Domain       string `json:"domain"`
	UseCachedDNS bool   `json:"useCachedDns"`
}

// Service defines the interface for the analysis service
type Service interface {
	AnalyzeDomain(domain string, useCachedDNS bool) (*httpAnalyzer.AnalysisResult, error)
}

// Config holds handler configuration
type Config struct {
	PublicDir    string
	TemplateDir  string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// Handler contains all HTTP handlers
type Handler struct {
	service Service
	config  *Config
}

// Dependencies holds all the service dependencies
type Dependencies struct {
	DNSResolver   dns.Resolver
	HTTPAnalyzer  httpAnalyzer.Analyzer
	TCPAnalyzer   tcp.Analyzer
	CSPEvaluator  csp.CSPEvaluator
}