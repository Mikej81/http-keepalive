package dns

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultDNSServer = "8.8.8.8:53"
	defaultTimeout   = 5 * time.Second
)

// ClientResolver implements the Resolver interface
type ClientResolver struct {
	config *Config
}

// NewResolver creates a new DNS resolver with the given configuration
func NewResolver(config *Config) *ClientResolver {
	if config == nil {
		config = &Config{
			UseCachedDNS: false,
			DNSServer:    defaultDNSServer,
			Timeout:      defaultTimeout,
		}
	}
	return &ClientResolver{config: config}
}

// ResolveDomain performs DNS resolution for the given domain
func (r *ClientResolver) ResolveDomain(domain string) (*Result, error) {
	var dnsServer string
	var err error

	if r.config.UseCachedDNS {
		dnsServer, err = r.GetSystemDNSServer()
		if err != nil {
			return nil, fmt.Errorf("failed to get system DNS server: %w", err)
		}
	} else {
		dnsServer = r.config.DNSServer
	}

	// Resolve CNAME records
	cnameRecords, err := r.resolveCNAME(domain)
	if err != nil && !isNotFoundError(err) {
		return nil, fmt.Errorf("failed to resolve CNAME records: %w", err)
	}

	// Resolve A records with TTL
	aRecords, err := r.resolveARecords(domain, dnsServer)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve A records: %w", err)
	}

	return &Result{
		CNAMERecords: cnameRecords,
		ARecords:     aRecords,
	}, nil
}

// GetSystemDNSServer reads the system's DNS server from /etc/resolv.conf
func (r *ClientResolver) GetSystemDNSServer() (string, error) {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("failed to open resolv.conf: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				return parts[1] + ":53", nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("failed to read resolv.conf: %w", err)
	}

	return "", fmt.Errorf("no nameserver found in resolv.conf")
}

// resolveCNAME resolves CNAME records for the domain
func (r *ClientResolver) resolveCNAME(domain string) ([]string, error) {
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		return nil, err
	}
	return []string{cname}, nil
}

// resolveARecords resolves A records with TTL information
func (r *ClientResolver) resolveARecords(domain, dnsServer string) ([]Record, error) {
	client := &dns.Client{
		Timeout: r.config.Timeout,
	}

	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	response, _, err := client.Exchange(message, dnsServer)
	if err != nil {
		return nil, fmt.Errorf("failed to query DNS: %w", err)
	}

	var records []Record
	for _, answer := range response.Answer {
		if aRecord, ok := answer.(*dns.A); ok {
			records = append(records, Record{
				IP:  aRecord.A.String(),
				TTL: time.Duration(aRecord.Header().Ttl) * time.Second,
			})
		}
	}

	return records, nil
}

// isNotFoundError checks if the error is a "not found" DNS error
func isNotFoundError(err error) bool {
	dnsErr, ok := err.(*net.DNSError)
	return ok && (dnsErr.Err == "no such host" || dnsErr.IsNotFound)
}