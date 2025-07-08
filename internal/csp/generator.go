package csp

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"
)

const (
	defaultTimeout = 30 * time.Second
	defaultUserAgent = "CSP-Generator/1.0"
	defaultMaxDepth = 1
)

// Client implements the Generator interface
type Client struct {
	config     *Config
	httpClient *http.Client
}

// NewGenerator creates a new CSP generator with the given configuration
func NewGenerator(config *Config) *Client {
	if config == nil {
		config = &Config{
			Timeout:         defaultTimeout,
			UserAgent:       defaultUserAgent,
			MaxDepth:        defaultMaxDepth,
			FollowRedirects: true,
		}
	}

	httpClient := &http.Client{
		Timeout: config.Timeout,
	}

	return &Client{
		config:     config,
		httpClient: httpClient,
	}
}

// GenerateCSP generates a Content Security Policy for the given page URL
func (c *Client) GenerateCSP(pageURL string) (string, error) {
	policy, err := c.AnalyzePage(pageURL)
	if err != nil {
		return "", fmt.Errorf("failed to analyze page: %w", err)
	}

	return c.buildCSPString(policy), nil
}

// AnalyzePage analyzes a web page and returns a CSP policy
func (c *Client) AnalyzePage(pageURL string) (*Policy, error) {
	resp, err := c.httpClient.Get(pageURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch page: %w", err)
	}
	defer resp.Body.Close()

	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	// Parse the HTML document
	doc, err := html.Parse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	policy := &Policy{
		ScriptSrc:      []string{"'self'"},
		StyleSrc:       []string{"'self'"},
		ImgSrc:         []string{"'self'"},
		FontSrc:        []string{"'self'"},
		MediaSrc:       []string{"'self'"},
		ConnectSrc:     []string{"'self'"},
		ObjectSrc:      []string{"'none'"}, // Default to none for security
		FrameSrc:       []string{"'self'"},
		ChildSrc:       []string{"'self'"},
		WorkerSrc:      []string{"'self'"},
		FrameAncestors: []string{"'none'"}, // Prevent clickjacking by default
		BaseURI:        []string{"'self'"}, // Prevent base tag injection
		FormAction:     []string{"'self'"}, // Restrict form submissions
		DefaultSrc:     []string{"'none'"}, // Default deny, then allowlist
		ManifestSrc:    []string{"'self'"},
	}

	// Analyze the document
	c.analyzeNode(doc, policy, parsedURL)

	return policy, nil
}

// analyzeNode recursively analyzes HTML nodes for CSP-relevant content
func (c *Client) analyzeNode(node *html.Node, policy *Policy, baseURL *url.URL) {
	if node.Type == html.ElementNode {
		switch node.Data {
		case "script":
			c.handleScriptElement(node, policy, baseURL)
		case "link":
			c.handleLinkElement(node, policy, baseURL)
		case "img":
			c.handleImageElement(node, policy, baseURL)
		case "video", "audio":
			c.handleMediaElement(node, policy, baseURL)
		case "source":
			c.handleSourceElement(node, policy, baseURL)
		case "object", "embed":
			c.handleObjectElement(node, policy, baseURL)
		case "iframe":
			c.handleIframeElement(node, policy, baseURL)
		case "style":
			c.handleStyleElement(node, policy)
		case "font":
			c.handleFontElement(node, policy, baseURL)
		case "base":
			c.handleBaseElement(node, policy, baseURL)
		case "form":
			c.handleFormElement(node, policy, baseURL)
		}
	}

	// Recursively analyze child nodes
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		c.analyzeNode(child, policy, baseURL)
	}
}

// handleScriptElement processes script elements
func (c *Client) handleScriptElement(node *html.Node, policy *Policy, baseURL *url.URL) {
	if src := c.getAttributeValue(node, "src"); src != "" {
		host := c.extractHost(src, baseURL)
		if host != "" && !c.contains(policy.ScriptSrc, host) {
			policy.ScriptSrc = append(policy.ScriptSrc, host)
		}
	} else {
		// Inline script - need unsafe-inline or hash
		if !c.contains(policy.ScriptSrc, "'unsafe-inline'") {
			policy.ScriptSrc = append(policy.ScriptSrc, "'unsafe-inline'")
		}
	}
}

// handleLinkElement processes link elements
func (c *Client) handleLinkElement(node *html.Node, policy *Policy, baseURL *url.URL) {
	if c.getAttributeValue(node, "rel") == "stylesheet" {
		if href := c.getAttributeValue(node, "href"); href != "" {
			host := c.extractHost(href, baseURL)
			if host != "" && !c.contains(policy.StyleSrc, host) {
				policy.StyleSrc = append(policy.StyleSrc, host)
			}
		}
	}
}

// handleImageElement processes img elements
func (c *Client) handleImageElement(node *html.Node, policy *Policy, baseURL *url.URL) {
	if src := c.getAttributeValue(node, "src"); src != "" {
		host := c.extractHost(src, baseURL)
		if host != "" && !c.contains(policy.ImgSrc, host) {
			policy.ImgSrc = append(policy.ImgSrc, host)
		}
	}
}

// handleMediaElement processes video and audio elements
func (c *Client) handleMediaElement(node *html.Node, policy *Policy, baseURL *url.URL) {
	if src := c.getAttributeValue(node, "src"); src != "" {
		host := c.extractHost(src, baseURL)
		if host != "" && !c.contains(policy.MediaSrc, host) {
			policy.MediaSrc = append(policy.MediaSrc, host)
		}
	}
}

// handleSourceElement processes source elements
func (c *Client) handleSourceElement(node *html.Node, policy *Policy, baseURL *url.URL) {
	if src := c.getAttributeValue(node, "src"); src != "" {
		host := c.extractHost(src, baseURL)
		if host != "" && !c.contains(policy.MediaSrc, host) {
			policy.MediaSrc = append(policy.MediaSrc, host)
		}
	}
}

// handleObjectElement processes object and embed elements
func (c *Client) handleObjectElement(node *html.Node, policy *Policy, baseURL *url.URL) {
	if data := c.getAttributeValue(node, "data"); data != "" {
		host := c.extractHost(data, baseURL)
		if host != "" && !c.contains(policy.ObjectSrc, host) {
			policy.ObjectSrc = append(policy.ObjectSrc, host)
		}
	}
}

// handleIframeElement processes iframe elements
func (c *Client) handleIframeElement(node *html.Node, policy *Policy, baseURL *url.URL) {
	if src := c.getAttributeValue(node, "src"); src != "" {
		host := c.extractHost(src, baseURL)
		if host != "" && !c.contains(policy.FrameSrc, host) {
			policy.FrameSrc = append(policy.FrameSrc, host)
		}
	}
}

// handleStyleElement processes style elements
func (c *Client) handleStyleElement(node *html.Node, policy *Policy) {
	// Inline styles need unsafe-inline or hashes
	if !c.contains(policy.StyleSrc, "'unsafe-inline'") {
		policy.StyleSrc = append(policy.StyleSrc, "'unsafe-inline'")
	}
}

// handleFontElement processes font elements
func (c *Client) handleFontElement(node *html.Node, policy *Policy, baseURL *url.URL) {
	if src := c.getAttributeValue(node, "src"); src != "" {
		host := c.extractHost(src, baseURL)
		if host != "" && !c.contains(policy.FontSrc, host) {
			policy.FontSrc = append(policy.FontSrc, host)
		}
	}
}

// handleBaseElement processes base elements
func (c *Client) handleBaseElement(node *html.Node, policy *Policy, baseURL *url.URL) {
	if href := c.getAttributeValue(node, "href"); href != "" {
		host := c.extractHost(href, baseURL)
		if host != "" && !c.contains(policy.BaseURI, host) {
			policy.BaseURI = append(policy.BaseURI, host)
		}
	}
}

// handleFormElement processes form elements
func (c *Client) handleFormElement(node *html.Node, policy *Policy, baseURL *url.URL) {
	if action := c.getAttributeValue(node, "action"); action != "" {
		host := c.extractHost(action, baseURL)
		if host != "" && !c.contains(policy.FormAction, host) {
			policy.FormAction = append(policy.FormAction, host)
		}
	}
}

// buildCSPString builds the CSP header string from a policy
func (c *Client) buildCSPString(policy *Policy) string {
	var builder strings.Builder

	// Define directive order for consistent output
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
	// Remove trailing semicolon and space
	if len(result) > 2 {
		result = result[:len(result)-2]
	}

	return result
}

// Helper methods

// getAttributeValue retrieves an attribute value from an HTML node
func (c *Client) getAttributeValue(node *html.Node, key string) string {
	for _, attr := range node.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

// extractHost extracts the host from a URL string
func (c *Client) extractHost(urlStr string, baseURL *url.URL) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}

	if parsedURL.IsAbs() {
		return parsedURL.Host
	}
	
	// For relative URLs, use the base URL's host
	return baseURL.Host
}

// contains checks if a slice contains a specific string
func (c *Client) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}