package csp

import (
	"fmt"
	"net/http"
	"strings"
)

// Evaluator provides comprehensive CSP evaluation functionality
type Evaluator struct {
	generator *Client
	parser    *PolicyParser
}

// NewEvaluator creates a new CSP evaluator
func NewEvaluator(config *Config) *Evaluator {
	return &Evaluator{
		generator: NewGenerator(config),
		parser:    NewParser(),
	}
}

// EvaluateCSP performs comprehensive CSP evaluation for a domain
func (e *Evaluator) EvaluateCSP(pageURL string, httpResponse *http.Response) (*CSPComparison, error) {
	// 1. Extract existing CSP from HTTP response
	existingCSP, err := e.parser.ExtractCSPFromResponse(httpResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to extract CSP from response: %w", err)
	}

	// 2. Analyze page content to generate optimal CSP
	optimalPolicy, err := e.generator.AnalyzePage(pageURL)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze page for optimal CSP: %w", err)
	}

	// 3. Enhance optimal policy with security best practices
	e.enhanceWithSecurityBestPractices(optimalPolicy)

	// 4. Validate existing CSP if present
	var validation *CSPValidation
	var improvements []CSPImprovement
	var securityScore int

	if existingCSP.HasCSP && existingCSP.Policy != nil {
		// Validate existing CSP against page content
		resources := e.extractResourcesFromPolicy(optimalPolicy)
		validation = e.parser.ValidateCSPEffectiveness(existingCSP.Policy, resources)
		
		// Compare existing vs optimal
		improvements = e.compareAndGenerateImprovements(existingCSP.Policy, optimalPolicy)
		securityScore = e.calculateSecurityScore(existingCSP.Policy, validation)
	} else {
		// No existing CSP - validate optimal policy
		resources := e.extractResourcesFromPolicy(optimalPolicy)
		validation = e.parser.ValidateCSPEffectiveness(optimalPolicy, resources)
		
		// Generate improvements for implementing CSP
		improvements = e.generateImplementationImprovements(optimalPolicy)
		securityScore = 0 // No CSP = zero security score
	}

	comparison := &CSPComparison{
		OptimalPolicy: optimalPolicy,
		Validation:    validation,
		Improvements:  improvements,
		SecurityScore: securityScore,
	}

	if existingCSP.HasCSP && existingCSP.Policy != nil {
		comparison.ExistingPolicy = existingCSP.Policy
	}

	return comparison, nil
}

// enhanceWithSecurityBestPractices adds security best practices to CSP policy
func (e *Evaluator) enhanceWithSecurityBestPractices(policy *Policy) {
	// Add essential security directives if missing
	if len(policy.FrameAncestors) == 0 {
		policy.FrameAncestors = []string{"'none'"}
	}
	
	if len(policy.BaseURI) == 0 {
		policy.BaseURI = []string{"'self'"}
	}
	
	if len(policy.FormAction) == 0 {
		policy.FormAction = []string{"'self'"}
	}
	
	if len(policy.ObjectSrc) == 0 {
		policy.ObjectSrc = []string{"'none'"}
	}

	// Remove unsafe directives and suggest better alternatives
	e.replaceUnsafeInline(policy)
}

// replaceUnsafeInline replaces 'unsafe-inline' with more secure alternatives
func (e *Evaluator) replaceUnsafeInline(policy *Policy) {
	// For script-src, prefer nonces over unsafe-inline
	if e.containsUnsafeInline(policy.ScriptSrc) {
		policy.ScriptSrc = e.removeUnsafeInline(policy.ScriptSrc)
		// Add comment about using nonces in production
		if !e.contains(policy.ScriptSrc, "'nonce-'") {
			policy.ScriptSrc = append(policy.ScriptSrc, "'nonce-{{NONCE}}'")
		}
	}
	
	// For style-src, allow unsafe-inline only if absolutely necessary
	if e.containsUnsafeInline(policy.StyleSrc) {
		// Keep unsafe-inline for styles for compatibility, but warn about it
		// In production, use nonces or hashes
	}
}

// compareAndGenerateImprovements compares existing and optimal policies
func (e *Evaluator) compareAndGenerateImprovements(existing, optimal *Policy) []CSPImprovement {
	var improvements []CSPImprovement

	// Compare each directive
	improvements = append(improvements, e.compareDirective("script-src", existing.ScriptSrc, optimal.ScriptSrc)...)
	improvements = append(improvements, e.compareDirective("style-src", existing.StyleSrc, optimal.StyleSrc)...)
	improvements = append(improvements, e.compareDirective("img-src", existing.ImgSrc, optimal.ImgSrc)...)
	improvements = append(improvements, e.compareDirective("font-src", existing.FontSrc, optimal.FontSrc)...)
	improvements = append(improvements, e.compareDirective("media-src", existing.MediaSrc, optimal.MediaSrc)...)
	improvements = append(improvements, e.compareDirective("connect-src", existing.ConnectSrc, optimal.ConnectSrc)...)
	improvements = append(improvements, e.compareDirective("object-src", existing.ObjectSrc, optimal.ObjectSrc)...)
	improvements = append(improvements, e.compareDirective("frame-ancestors", existing.FrameAncestors, optimal.FrameAncestors)...)
	improvements = append(improvements, e.compareDirective("base-uri", existing.BaseURI, optimal.BaseURI)...)
	improvements = append(improvements, e.compareDirective("form-action", existing.FormAction, optimal.FormAction)...)

	return improvements
}

// compareDirective compares existing vs optimal directive values
func (e *Evaluator) compareDirective(directive string, existing, optimal []string) []CSPImprovement {
	var improvements []CSPImprovement

	// Check for missing sources in existing policy
	for _, source := range optimal {
		if !e.contains(existing, source) {
			improvements = append(improvements, CSPImprovement{
				Type:             "add",
				Directive:        directive,
				RecommendedValue: source,
				Reason:           "Required source missing from current policy",
				Impact:           e.getImpactLevel(directive, source),
			})
		}
	}

	// Check for unnecessary or dangerous sources in existing policy
	for _, source := range existing {
		if e.isUnsafeSource(source) {
			improvements = append(improvements, CSPImprovement{
				Type:             "remove",
				Directive:        directive,
				CurrentValue:     source,
				RecommendedValue: e.getSaferAlternative(source),
				Reason:           "Unsafe source reduces security",
				Impact:           "high",
			})
		} else if !e.contains(optimal, source) && !e.isEssentialSource(source) {
			improvements = append(improvements, CSPImprovement{
				Type:         "remove",
				Directive:    directive,
				CurrentValue: source,
				Reason:       "Unnecessary source increases attack surface",
				Impact:       "medium",
			})
		}
	}

	return improvements
}

// generateImplementationImprovements generates improvements for implementing CSP
func (e *Evaluator) generateImplementationImprovements(optimal *Policy) []CSPImprovement {
	var improvements []CSPImprovement

	improvements = append(improvements, CSPImprovement{
		Type:             "add",
		Directive:        "header",
		RecommendedValue: e.buildCSPString(optimal),
		Reason:           "No Content Security Policy header found",
		Impact:           "high",
	})

	return improvements
}

// calculateSecurityScore calculates a security score for the CSP policy
func (e *Evaluator) calculateSecurityScore(policy *Policy, validation *CSPValidation) int {
	score := 100
	
	// Deduct points for issues
	for _, issue := range validation.Issues {
		switch issue.Severity {
		case "high":
			score -= 20
		case "medium":
			score -= 10
		case "low":
			score -= 5
		}
	}
	
	// Deduct points for warnings
	score -= len(validation.Warnings) * 2
	
	// Bonus points for security directives
	if len(policy.FrameAncestors) > 0 && !e.contains(policy.FrameAncestors, "'none'") {
		score += 5
	}
	if len(policy.BaseURI) > 0 {
		score += 5
	}
	if len(policy.FormAction) > 0 {
		score += 5
	}
	
	// Ensure score is between 0 and 100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	
	return score
}

// extractResourcesFromPolicy extracts resources from a policy for validation
func (e *Evaluator) extractResourcesFromPolicy(policy *Policy) []*Resource {
	var resources []*Resource
	
	// Extract script resources
	for _, source := range policy.ScriptSrc {
		if source != "'self'" && source != "'unsafe-inline'" && !strings.HasPrefix(source, "'nonce-") {
			resources = append(resources, &Resource{
				URL:       source,
				Type:      "external",
				Directive: "script-src",
				IsInline:  false,
			})
		}
	}
	
	// Extract style resources
	for _, source := range policy.StyleSrc {
		if source != "'self'" && source != "'unsafe-inline'" && !strings.HasPrefix(source, "'nonce-") {
			resources = append(resources, &Resource{
				URL:       source,
				Type:      "external", 
				Directive: "style-src",
				IsInline:  false,
			})
		}
	}
	
	// Extract image resources
	for _, source := range policy.ImgSrc {
		if source != "'self'" && source != "data:" {
			resources = append(resources, &Resource{
				URL:       source,
				Type:      "external",
				Directive: "img-src",
				IsInline:  false,
			})
		}
	}
	
	return resources
}

// Helper methods

func (e *Evaluator) buildCSPString(policy *Policy) string {
	return e.generator.buildCSPString(policy)
}

func (e *Evaluator) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (e *Evaluator) containsUnsafeInline(sources []string) bool {
	return e.contains(sources, "'unsafe-inline'")
}

func (e *Evaluator) removeUnsafeInline(sources []string) []string {
	var result []string
	for _, source := range sources {
		if source != "'unsafe-inline'" {
			result = append(result, source)
		}
	}
	return result
}

func (e *Evaluator) isUnsafeSource(source string) bool {
	unsafeSources := []string{"'unsafe-inline'", "'unsafe-eval'", "*", "data:", "http:"}
	return e.contains(unsafeSources, source)
}

func (e *Evaluator) isEssentialSource(source string) bool {
	essentialSources := []string{"'self'", "'none'"}
	return e.contains(essentialSources, source)
}

func (e *Evaluator) getSaferAlternative(unsafeSource string) string {
	alternatives := map[string]string{
		"'unsafe-inline'": "'nonce-' or hash values",
		"'unsafe-eval'":   "Avoid eval() and similar functions",
		"*":               "Specific domain allowlist",
		"data:":           "Specific domains or 'self'",
		"http:":           "https: or specific HTTPS domains",
	}
	
	if alt, exists := alternatives[unsafeSource]; exists {
		return alt
	}
	
	return "More restrictive source"
}

func (e *Evaluator) getImpactLevel(directive, source string) string {
	// High impact for script and object sources
	if directive == "script-src" || directive == "object-src" {
		return "high"
	}
	
	// Medium impact for style and frame directives
	if directive == "style-src" || directive == "frame-ancestors" {
		return "medium"
	}
	
	// Lower impact for other directives
	return "low"
}