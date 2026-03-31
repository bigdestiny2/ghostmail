// Package dmarc implements a basic DMARC (Domain-based Message Authentication,
// Reporting, and Conformance) checker. It looks up the _dmarc TXT record,
// parses the policy, and checks SPF/DKIM alignment against the RFC5322 From domain.
package dmarc

import (
	"net"
	"strings"
)

// Policy constants.
const (
	PolicyNone       = "none"
	PolicyQuarantine = "quarantine"
	PolicyReject     = "reject"
)

// Result holds the outcome of a DMARC evaluation.
type Result struct {
	Policy string // "none", "quarantine", "reject"
	Pass   bool   // true if at least one mechanism is aligned and passes
	HasRecord bool // true if a _dmarc record was found
}

// Resolver abstracts DNS lookups so tests can inject fakes.
type Resolver interface {
	LookupTXT(domain string) ([]string, error)
}

// netResolver uses the standard library.
type netResolver struct{}

func (netResolver) LookupTXT(domain string) ([]string, error) {
	return net.LookupTXT(domain)
}

// DefaultResolver is the production DNS resolver.
var DefaultResolver Resolver = netResolver{}

// Check evaluates DMARC for the given From header domain.
//
// Parameters:
//   - fromDomain: the domain from the RFC5322 From header
//   - spfResult:  the SPF check result ("pass", "fail", etc.)
//   - spfDomain:  the domain used for SPF (MAIL FROM envelope domain)
//   - dkimResult: the DKIM check result ("pass", "fail", "none")
//   - dkimDomain: the d= domain from the DKIM signature
//
// Returns the DMARC policy and whether the message passes DMARC.
func Check(fromDomain, spfResult, spfDomain, dkimResult, dkimDomain string) *Result {
	return CheckWithResolver(fromDomain, spfResult, spfDomain, dkimResult, dkimDomain, DefaultResolver)
}

// CheckWithResolver performs a DMARC check using the provided resolver.
func CheckWithResolver(fromDomain, spfResult, spfDomain, dkimResult, dkimDomain string, resolver Resolver) *Result {
	result := &Result{
		Policy:    PolicyNone,
		Pass:      false,
		HasRecord: false,
	}

	// Look up _dmarc.<fromDomain>
	dmarcDomain := "_dmarc." + fromDomain
	txts, err := resolver.LookupTXT(dmarcDomain)
	if err != nil {
		return result
	}

	// Find the DMARC record
	var dmarcRecord string
	for _, txt := range txts {
		trimmed := strings.TrimSpace(txt)
		if strings.HasPrefix(strings.ToLower(trimmed), "v=dmarc1") {
			dmarcRecord = trimmed
			break
		}
	}
	if dmarcRecord == "" {
		return result
	}
	result.HasRecord = true

	// Parse tags
	tags := parseTags(dmarcRecord)

	// Extract policy
	if p, ok := tags["p"]; ok {
		switch strings.ToLower(p) {
		case "reject":
			result.Policy = PolicyReject
		case "quarantine":
			result.Policy = PolicyQuarantine
		default:
			result.Policy = PolicyNone
		}
	}

	// Determine alignment mode (default: relaxed)
	aspf := "r" // relaxed
	adkim := "r"
	if v, ok := tags["aspf"]; ok {
		aspf = strings.ToLower(v)
	}
	if v, ok := tags["adkim"]; ok {
		adkim = strings.ToLower(v)
	}

	// Check SPF alignment
	spfAligned := false
	if strings.ToLower(spfResult) == "pass" && spfDomain != "" {
		spfAligned = domainsAligned(fromDomain, spfDomain, aspf)
	}

	// Check DKIM alignment
	dkimAligned := false
	if strings.ToLower(dkimResult) == "pass" && dkimDomain != "" {
		dkimAligned = domainsAligned(fromDomain, dkimDomain, adkim)
	}

	// DMARC passes if either mechanism is aligned and passes
	result.Pass = spfAligned || dkimAligned

	return result
}

// parseTags splits a DMARC record into tag-value pairs.
// Example: "v=DMARC1; p=reject; adkim=s; aspf=s" =>
//
//	{"v": "DMARC1", "p": "reject", "adkim": "s", "aspf": "s"}
func parseTags(record string) map[string]string {
	tags := make(map[string]string)
	parts := strings.Split(record, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.Index(part, "=")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(part[:idx]))
		value := strings.TrimSpace(part[idx+1:])
		tags[key] = value
	}
	return tags
}

// domainsAligned checks whether two domains align under DMARC rules.
// mode "s" = strict (exact match), mode "r" = relaxed (organizational domain match).
func domainsAligned(fromDomain, authDomain, mode string) bool {
	from := strings.ToLower(strings.TrimSuffix(fromDomain, "."))
	auth := strings.ToLower(strings.TrimSuffix(authDomain, "."))

	if mode == "s" {
		// Strict: exact match
		return from == auth
	}

	// Relaxed: the organizational domains must match.
	// Simple heuristic: use the last two labels (e.g., example.com).
	// This doesn't handle public suffix list edge cases (co.uk, etc.)
	// but works for the vast majority of domains.
	return orgDomain(from) == orgDomain(auth)
}

// orgDomain extracts the organizational domain (last two labels) from a domain.
func orgDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
