package csp

import (
	"net/http"
	"strings"
)

// PolicyParser implements CSP header parsing functionality
type PolicyParser struct{}

// NewParser creates a new CSP parser
func NewParser() *PolicyParser {
	return &PolicyParser{}
}

// ParseCSPHeader parses a CSP header string into a Policy struct
func (p *PolicyParser) ParseCSPHeader(cspHeader string) (*Policy, error) {
	policy := &Policy{
		ScriptSrc:     []string{},
		StyleSrc:      []string{},
		ImgSrc:        []string{},
		FontSrc:       []string{},
		MediaSrc:      []string{},
		ConnectSrc:    []string{},
		ObjectSrc:     []string{},
		FrameSrc:      []string{},
		ChildSrc:      []string{},
		WorkerSrc:     []string{},
		FrameAncestors: []string{},
		BaseURI:       []string{},
		FormAction:    []string{},
		DefaultSrc:    []string{},
		ManifestSrc:   []string{},
	}

	if cspHeader == "" {
		return policy, nil
	}

	// Split CSP header into directives
	directives := strings.Split(cspHeader, ";")
	
	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if directive == "" {
			continue
		}
		
		// Split directive into name and sources
		parts := strings.Fields(directive)
		if len(parts) == 0 {
			continue
		}
		
		directiveName := strings.ToLower(parts[0])
		sources := parts[1:]
		
		// Map directive to policy field
		switch directiveName {
		case "script-src":
			policy.ScriptSrc = sources
		case "style-src":
			policy.StyleSrc = sources
		case "img-src":
			policy.ImgSrc = sources
		case "font-src":
			policy.FontSrc = sources
		case "media-src":
			policy.MediaSrc = sources
		case "connect-src":
			policy.ConnectSrc = sources
		case "object-src":
			policy.ObjectSrc = sources
		case "frame-src":
			policy.FrameSrc = sources
		case "child-src":
			policy.ChildSrc = sources
		case "worker-src":
			policy.WorkerSrc = sources
		case "frame-ancestors":
			policy.FrameAncestors = sources
		case "base-uri":
			policy.BaseURI = sources
		case "form-action":
			policy.FormAction = sources
		case "default-src":
			policy.DefaultSrc = sources
		case "manifest-src":
			policy.ManifestSrc = sources
		}
	}
	
	return policy, nil
}

// ExtractCSPFromResponse extracts CSP headers from HTTP response
func (p *PolicyParser) ExtractCSPFromResponse(resp *http.Response) (*CSPAnalysis, error) {
	analysis := &CSPAnalysis{
		HasCSP: false,
		Headers: make(map[string]string),
	}
	
	// Check for CSP headers
	cspHeader := resp.Header.Get("Content-Security-Policy")
	cspReportOnlyHeader := resp.Header.Get("Content-Security-Policy-Report-Only")
	
	if cspHeader != "" {
		analysis.HasCSP = true
		analysis.Headers["Content-Security-Policy"] = cspHeader
		policy, err := p.ParseCSPHeader(cspHeader)
		if err != nil {
			return analysis, err
		}
		analysis.Policy = policy
	}
	
	if cspReportOnlyHeader != "" {
		analysis.Headers["Content-Security-Policy-Report-Only"] = cspReportOnlyHeader
		policy, err := p.ParseCSPHeader(cspReportOnlyHeader)
		if err != nil {
			return analysis, err
		}
		analysis.ReportOnlyPolicy = policy
	}
	
	return analysis, nil
}

// ValidateCSPEffectiveness validates a CSP policy against page resources
func (p *PolicyParser) ValidateCSPEffectiveness(policy *Policy, resources []*Resource) *CSPValidation {
	validation := &CSPValidation{
		IsEffective: true,
		Issues:      []CSPIssue{},
		Warnings:    []CSPWarning{},
	}
	
	// Check for unsafe directives
	p.checkUnsafeDirectives(policy, validation)
	
	// Check for missing directives
	p.checkMissingDirectives(policy, validation)
	
	// Check resource coverage
	p.checkResourceCoverage(policy, resources, validation)
	
	// Check for overly permissive directives
	p.checkPermissiveDirectives(policy, validation)
	
	return validation
}

// checkUnsafeDirectives identifies potentially unsafe CSP directives
func (p *PolicyParser) checkUnsafeDirectives(policy *Policy, validation *CSPValidation) {
	unsafeChecks := map[string][]string{
		"script-src": policy.ScriptSrc,
		"style-src":  policy.StyleSrc,
		"object-src": policy.ObjectSrc,
	}
	
	for directive, sources := range unsafeChecks {
		for _, source := range sources {
			switch source {
			case "'unsafe-inline'":
				validation.Issues = append(validation.Issues, CSPIssue{
					Severity:    "high",
					Directive:   directive,
					Source:      source,
					Message:     "Using 'unsafe-inline' defeats XSS protection",
					Recommendation: "Use nonces or hashes instead of 'unsafe-inline'",
				})
			case "'unsafe-eval'":
				validation.Issues = append(validation.Issues, CSPIssue{
					Severity:    "high", 
					Directive:   directive,
					Source:      source,
					Message:     "Using 'unsafe-eval' allows code execution",
					Recommendation: "Remove 'unsafe-eval' and avoid eval(), setTimeout() with strings",
				})
			case "*":
				validation.Issues = append(validation.Issues, CSPIssue{
					Severity:    "medium",
					Directive:   directive,
					Source:      source,
					Message:     "Wildcard (*) allows any source",
					Recommendation: "Specify explicit allowed sources instead of wildcard",
				})
			}
		}
	}
}

// checkMissingDirectives identifies important missing CSP directives
func (p *PolicyParser) checkMissingDirectives(policy *Policy, validation *CSPValidation) {
	criticalDirectives := map[string][]string{
		"frame-ancestors": policy.FrameAncestors,
		"base-uri":        policy.BaseURI,
		"form-action":     policy.FormAction,
	}
	
	for directive, sources := range criticalDirectives {
		if len(sources) == 0 && len(policy.DefaultSrc) == 0 {
			validation.Warnings = append(validation.Warnings, CSPWarning{
				Directive: directive,
				Message:   "Missing important security directive",
				Recommendation: p.getDirectiveRecommendation(directive),
			})
		}
	}
}

// checkResourceCoverage validates that CSP covers all page resources
func (p *PolicyParser) checkResourceCoverage(policy *Policy, resources []*Resource, validation *CSPValidation) {
	for _, resource := range resources {
		if !p.isResourceCovered(policy, resource) {
			validation.Issues = append(validation.Issues, CSPIssue{
				Severity:    "medium",
				Directive:   resource.Directive,
				Source:      resource.URL,
				Message:     "Resource not covered by CSP directive",
				Recommendation: "Add resource origin to appropriate CSP directive",
			})
		}
	}
}

// checkPermissiveDirectives identifies overly permissive CSP settings
func (p *PolicyParser) checkPermissiveDirectives(policy *Policy, validation *CSPValidation) {
	if p.containsSource(policy.ScriptSrc, "https:") {
		validation.Warnings = append(validation.Warnings, CSPWarning{
			Directive: "script-src",
			Message:   "Allowing all HTTPS scripts may be too permissive",
			Recommendation: "Consider restricting to specific trusted domains",
		})
	}
	
	if p.containsSource(policy.StyleSrc, "https:") {
		validation.Warnings = append(validation.Warnings, CSPWarning{
			Directive: "style-src", 
			Message:   "Allowing all HTTPS stylesheets may be too permissive",
			Recommendation: "Consider restricting to specific trusted domains",
		})
	}
}

// isResourceCovered checks if a resource is covered by CSP policy
func (p *PolicyParser) isResourceCovered(policy *Policy, resource *Resource) bool {
	var sources []string
	
	switch resource.Directive {
	case "script-src":
		sources = policy.ScriptSrc
	case "style-src":
		sources = policy.StyleSrc
	case "img-src":
		sources = policy.ImgSrc
	case "font-src":
		sources = policy.FontSrc
	case "media-src":
		sources = policy.MediaSrc
	case "connect-src":
		sources = policy.ConnectSrc
	case "object-src":
		sources = policy.ObjectSrc
	default:
		sources = policy.DefaultSrc
	}
	
	// If no specific directive, fall back to default-src
	if len(sources) == 0 {
		sources = policy.DefaultSrc
	}
	
	for _, source := range sources {
		if p.sourceMatchesResource(source, resource) {
			return true
		}
	}
	
	return false
}

// sourceMatchesResource checks if a CSP source matches a resource
func (p *PolicyParser) sourceMatchesResource(source string, resource *Resource) bool {
	switch source {
	case "'self'":
		return resource.Type == "self"
	case "'unsafe-inline'":
		return resource.IsInline
	case "*":
		return true
	case "data:":
		return strings.HasPrefix(resource.URL, "data:")
	case "https:":
		return strings.HasPrefix(resource.URL, "https:")
	case "http:":
		return strings.HasPrefix(resource.URL, "http:")
	default:
		// Check if source matches resource URL host
		return strings.Contains(resource.URL, source)
	}
}

// containsSource checks if sources slice contains a specific source
func (p *PolicyParser) containsSource(sources []string, source string) bool {
	for _, s := range sources {
		if s == source {
			return true
		}
	}
	return false
}

// getDirectiveRecommendation returns security recommendation for directive
func (p *PolicyParser) getDirectiveRecommendation(directive string) string {
	recommendations := map[string]string{
		"frame-ancestors": "Add 'frame-ancestors 'none'' to prevent clickjacking",
		"base-uri":        "Add 'base-uri 'self'' to prevent base tag injection",
		"form-action":     "Add 'form-action 'self'' to restrict form submissions",
		"object-src":      "Add 'object-src 'none'' to block plugins",
	}
	
	if rec, exists := recommendations[directive]; exists {
		return rec
	}
	
	return "Consider adding this directive for better security"
}