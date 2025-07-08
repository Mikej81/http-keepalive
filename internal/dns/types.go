package dns

import "time"

// Record represents a DNS record with associated metadata
type Record struct {
	IP  string        `json:"ip"`
	TTL time.Duration `json:"ttl"`
}

// Result contains the results of a DNS lookup
type Result struct {
	CNAMERecords []string `json:"cnameRecords"`
	ARecords     []Record `json:"aRecords"`
}

// Config holds DNS resolver configuration
type Config struct {
	UseCachedDNS bool
	DNSServer    string
	Timeout      time.Duration
}

// Resolver defines the interface for DNS resolution
type Resolver interface {
	ResolveDomain(domain string) (*Result, error)
	GetSystemDNSServer() (string, error)
}