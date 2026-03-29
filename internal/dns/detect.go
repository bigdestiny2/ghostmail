package dns

import (
	"fmt"
	"net"
	"strings"
)

// ProviderHint identifies a DNS provider from nameserver patterns.
type ProviderHint struct {
	Name     string
	Patterns []string
}

var knownProviders = []ProviderHint{
	{Name: "cloudflare", Patterns: []string{".ns.cloudflare.com"}},
	{Name: "digitalocean", Patterns: []string{".digitalocean.com"}},
	{Name: "route53", Patterns: []string{".awsdns-"}},
	{Name: "namecheap", Patterns: []string{".registrar-servers.com"}},
	{Name: "google", Patterns: []string{".googledomains.com", ".google.com"}},
	{Name: "godaddy", Patterns: []string{".domaincontrol.com"}},
	{Name: "hetzner", Patterns: []string{".hetzner.com"}},
	{Name: "vultr", Patterns: []string{".vultr.com"}},
	{Name: "linode", Patterns: []string{".linode.com"}},
	{Name: "porkbun", Patterns: []string{".porkbun.com"}},
	{Name: "vercel", Patterns: []string{".vercel-dns.com"}},
}

// DetectProvider looks up the nameservers for a domain and returns
// the detected DNS provider name. Returns empty string if unknown.
func DetectProvider(domain string) (string, error) {
	nameservers, err := net.LookupNS(domain)
	if err != nil {
		return "", fmt.Errorf("NS lookup failed for %s: %w", domain, err)
	}

	for _, ns := range nameservers {
		host := strings.ToLower(strings.TrimSuffix(ns.Host, "."))
		for _, provider := range knownProviders {
			for _, pattern := range provider.Patterns {
				if strings.Contains(host, pattern) {
					return provider.Name, nil
				}
			}
		}
	}

	// Return nameservers for debugging
	hosts := make([]string, len(nameservers))
	for i, ns := range nameservers {
		hosts[i] = ns.Host
	}
	return "", fmt.Errorf("unknown provider, nameservers: %s", strings.Join(hosts, ", "))
}

// NewProvider creates a DNS provider client from a name and API credentials.
func NewProvider(name, apiKey, apiExtra string) (Provider, error) {
	switch strings.ToLower(name) {
	case "cloudflare":
		return NewCloudflare(apiKey), nil
	case "digitalocean":
		return NewDigitalOcean(apiKey), nil
	default:
		return nil, fmt.Errorf("unsupported DNS provider: %s (supported: cloudflare, digitalocean)", name)
	}
}
