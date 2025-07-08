package csp

import (
	"net/http"
	"time"
)

// Policy represents a Content Security Policy
type Policy struct {
	ScriptSrc      []string `json:"scriptSrc"`
	StyleSrc       []string `json:"styleSrc"`
	ImgSrc         []string `json:"imgSrc"`
	FontSrc        []string `json:"fontSrc"`
	MediaSrc       []string `json:"mediaSrc"`
	ConnectSrc     []string `json:"connectSrc"`
	ObjectSrc      []string `json:"objectSrc"`
	FrameSrc       []string `json:"frameSrc"`
	ChildSrc       []string `json:"childSrc"`
	WorkerSrc      []string `json:"workerSrc"`
	FrameAncestors []string `json:"frameAncestors"`
	BaseURI        []string `json:"baseUri"`
	FormAction     []string `json:"formAction"`
	DefaultSrc     []string `json:"defaultSrc"`
	ManifestSrc    []string `json:"manifestSrc"`
}

// Config holds CSP generator configuration
type Config struct {
	Timeout    time.Duration
	UserAgent  string
	MaxDepth   int
	FollowRedirects bool
}

// Generator defines the interface for CSP generation
type Generator interface {
	GenerateCSP(pageURL string) (string, error)
	AnalyzePage(pageURL string) (*Policy, error)
}

// CSPEvaluator defines the interface for comprehensive CSP evaluation
type CSPEvaluator interface {
	EvaluateCSP(pageURL string, httpResponse *http.Response) (*CSPComparison, error)
}

// Parser defines the interface for HTML parsing
type Parser interface {
	ParseHTML(content []byte, baseURL string) (*Policy, error)
}

// Resource represents a web resource found during analysis
type Resource struct {
	URL        string
	Type       string
	Directive  string
	IsInline   bool
	Hash       string
}

// CSPAnalysis represents the result of CSP header analysis
type CSPAnalysis struct {
	HasCSP           bool               `json:"hasCSP"`
	Headers          map[string]string  `json:"headers"`
	Policy           *Policy            `json:"policy,omitempty"`
	ReportOnlyPolicy *Policy            `json:"reportOnlyPolicy,omitempty"`
}

// CSPValidation represents the validation result of a CSP policy
type CSPValidation struct {
	IsEffective bool         `json:"isEffective"`
	Issues      []CSPIssue   `json:"issues"`
	Warnings    []CSPWarning `json:"warnings"`
}

// CSPIssue represents a security issue with the CSP policy
type CSPIssue struct {
	Severity       string `json:"severity"`
	Directive      string `json:"directive"`
	Source         string `json:"source"`
	Message        string `json:"message"`
	Recommendation string `json:"recommendation"`
}

// CSPWarning represents a warning about the CSP policy
type CSPWarning struct {
	Directive      string `json:"directive"`
	Message        string `json:"message"`
	Recommendation string `json:"recommendation"`
}

// CSPComparison represents a comparison between existing and optimal CSP
type CSPComparison struct {
	ExistingPolicy   *Policy            `json:"existingPolicy,omitempty"`
	OptimalPolicy    *Policy            `json:"optimalPolicy"`
	Validation       *CSPValidation     `json:"validation"`
	Improvements     []CSPImprovement   `json:"improvements"`
	SecurityScore    int                `json:"securityScore"`
}

// CSPImprovement represents a recommended improvement to CSP
type CSPImprovement struct {
	Type           string `json:"type"`           // "add", "remove", "modify"
	Directive      string `json:"directive"`
	CurrentValue   string `json:"currentValue,omitempty"`
	RecommendedValue string `json:"recommendedValue"`
	Reason         string `json:"reason"`
	Impact         string `json:"impact"`         // "high", "medium", "low"
}