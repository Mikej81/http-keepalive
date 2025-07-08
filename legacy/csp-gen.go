package main

import (
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

func generateCSP(pageURL string) (string, error) {
	resp, err := http.Get(pageURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		return "", err
	}

	// Initialize directives
	resourceDomains := make(map[string]map[string]struct{})
	resourceDomains["script-src"] = make(map[string]struct{})
	resourceDomains["style-src"] = make(map[string]struct{})
	resourceDomains["img-src"] = make(map[string]struct{})
	resourceDomains["font-src"] = make(map[string]struct{})
	resourceDomains["media-src"] = make(map[string]struct{})
	resourceDomains["connect-src"] = make(map[string]struct{})
	resourceDomains["object-src"] = make(map[string]struct{})

	// Parse the HTML
	doc, err := html.Parse(resp.Body)
	if err != nil {
		return "", err
	}

	var crawl func(*html.Node)
	crawl = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "script":
				addToCSP(n, "src", "script-src", resourceDomains, parsedURL)
			case "link":
				if attrValue(n, "rel") == "stylesheet" {
					addToCSP(n, "href", "style-src", resourceDomains, parsedURL)
				}
			case "img":
				addToCSP(n, "src", "img-src", resourceDomains, parsedURL)
			case "video", "audio":
				addToCSP(n, "src", "media-src", resourceDomains, parsedURL)
			case "source": // For <source> tags in <video>/<audio>
				addToCSP(n, "src", "media-src", resourceDomains, parsedURL)
			case "object", "embed":
				addToCSP(n, "data", "object-src", resourceDomains, parsedURL)
			case "iframe":
				addToCSP(n, "src", "connect-src", resourceDomains, parsedURL)
			case "style":
				// Inline styles need unsafe-inline or hashes
				resourceDomains["style-src"]["'unsafe-inline'"] = struct{}{}
			case "font":
				addToCSP(n, "src", "font-src", resourceDomains, parsedURL)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			crawl(c)
		}
	}

	crawl(doc)

	// Build CSP string
	var cspBuilder strings.Builder
	for directive, sources := range resourceDomains {
		cspBuilder.WriteString(directive)
		cspBuilder.WriteString(" ")
		cspBuilder.WriteString("'self'")
		for source := range sources {
			cspBuilder.WriteString(" ")
			cspBuilder.WriteString(source)
		}
		cspBuilder.WriteString("; ")
	}
	return cspBuilder.String(), nil
}

func addToCSP(n *html.Node, attrName, directive string, domains map[string]map[string]struct{}, baseURL *url.URL) {
	for _, attr := range n.Attr {
		if attr.Key == attrName {
			parsedURL, err := url.Parse(attr.Val)
			if err == nil {
				if parsedURL.IsAbs() {
					domains[directive][parsedURL.Host] = struct{}{}
				} else {
					domains[directive][baseURL.Host] = struct{}{}
				}
			}
			break
		}
	}
}

func attrValue(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}
