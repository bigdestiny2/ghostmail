// Package spf implements a basic SPF (Sender Policy Framework) checker.
// It handles the most common SPF mechanisms: ip4, ip6, mx, a, include, and all.
// Macros and advanced modifiers (redirect, exp) are not supported.
package spf

import (
	"net"
	"strings"
)

// Result constants matching RFC 7208 terminology.
const (
	ResultPass     = "pass"
	ResultFail     = "fail"
	ResultSoftFail = "softfail"
	ResultNeutral  = "neutral"
	ResultNone     = "none"
	ResultTempError = "temperror"
)

// maxIncludeDepth prevents infinite recursion on include chains.
const maxIncludeDepth = 3

// Resolver abstracts DNS lookups so tests can inject fakes.
type Resolver interface {
	LookupTXT(domain string) ([]string, error)
	LookupIPAddr(host string) ([]net.IP, error)
	LookupMX(domain string) ([]*net.MX, error)
}

// netResolver implements Resolver using the standard net package.
type netResolver struct{}

func (netResolver) LookupTXT(domain string) ([]string, error) {
	return net.LookupTXT(domain)
}

func (netResolver) LookupIPAddr(host string) ([]net.IP, error) {
	addrs, err := net.LookupIP(host)
	return addrs, err
}

func (netResolver) LookupMX(domain string) ([]*net.MX, error) {
	return net.LookupMX(domain)
}

// DefaultResolver is the production DNS resolver.
var DefaultResolver Resolver = netResolver{}

// Check performs an SPF check for the given IP against the sender domain.
// It returns one of: "pass", "fail", "softfail", "neutral", "none", "temperror".
func Check(ip net.IP, senderDomain string) string {
	return checkWithResolver(ip, senderDomain, DefaultResolver, 0)
}

// CheckWithResolver performs an SPF check using the provided resolver.
func CheckWithResolver(ip net.IP, senderDomain string, resolver Resolver) string {
	return checkWithResolver(ip, senderDomain, resolver, 0)
}

func checkWithResolver(ip net.IP, senderDomain string, resolver Resolver, depth int) string {
	if depth > maxIncludeDepth {
		return ResultTempError
	}

	txts, err := resolver.LookupTXT(senderDomain)
	if err != nil {
		return ResultNone
	}

	// Find the SPF record (RFC 7208 sec 4.5: exactly one v=spf1 record)
	var spfRecord string
	for _, txt := range txts {
		trimmed := strings.TrimSpace(txt)
		if strings.HasPrefix(strings.ToLower(trimmed), "v=spf1") {
			// Ensure it's "v=spf1" followed by space or end of string
			rest := trimmed[6:]
			if rest == "" || rest[0] == ' ' || rest[0] == '\t' {
				spfRecord = trimmed
				break
			}
		}
	}
	if spfRecord == "" {
		return ResultNone
	}

	return evaluate(ip, senderDomain, spfRecord, resolver, depth)
}

// evaluate processes the mechanisms in an SPF record left-to-right.
func evaluate(ip net.IP, domain, record string, resolver Resolver, depth int) string {
	// Split the record into tokens (skip "v=spf1")
	tokens := strings.Fields(record)
	if len(tokens) < 1 {
		return ResultNone
	}
	tokens = tokens[1:] // skip "v=spf1"

	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}

		qualifier, mechanism := parseQualifier(token)

		matched := false
		switch {
		case mechanism == "all":
			matched = true
		case strings.HasPrefix(mechanism, "ip4:"):
			matched = matchIP4(ip, mechanism[4:])
		case strings.HasPrefix(mechanism, "ip6:"):
			matched = matchIP6(ip, mechanism[4:])
		case mechanism == "a" || strings.HasPrefix(mechanism, "a:"):
			target := domain
			if strings.HasPrefix(mechanism, "a:") {
				target = mechanism[2:]
			}
			matched = matchA(ip, target, resolver)
		case mechanism == "mx" || strings.HasPrefix(mechanism, "mx:"):
			target := domain
			if strings.HasPrefix(mechanism, "mx:") {
				target = mechanism[3:]
			}
			matched = matchMX(ip, target, resolver)
		case strings.HasPrefix(mechanism, "include:"):
			includeDomain := mechanism[8:]
			result := checkWithResolver(ip, includeDomain, resolver, depth+1)
			if result == ResultPass {
				matched = true
			}
			// For include, only "pass" from the included check counts as a match.
			// Other results are ignored and we continue to next mechanism.
		default:
			// Unknown mechanism; skip (redirect, exists, etc. not implemented)
			continue
		}

		if matched {
			return qualifierToResult(qualifier)
		}
	}

	// Default result if no mechanism matched (implicit "?all")
	return ResultNeutral
}

// parseQualifier splits a mechanism token into its qualifier (+, -, ~, ?)
// and the mechanism itself. Default qualifier is "+".
func parseQualifier(token string) (qualifier byte, mechanism string) {
	if len(token) == 0 {
		return '+', ""
	}
	switch token[0] {
	case '+', '-', '~', '?':
		return token[0], strings.ToLower(token[1:])
	default:
		return '+', strings.ToLower(token)
	}
}

// qualifierToResult converts an SPF qualifier to a result string.
func qualifierToResult(q byte) string {
	switch q {
	case '+':
		return ResultPass
	case '-':
		return ResultFail
	case '~':
		return ResultSoftFail
	case '?':
		return ResultNeutral
	default:
		return ResultNeutral
	}
}

// matchIP4 checks if the given IP matches an ip4 mechanism value.
// The value can be a single IP or a CIDR range (e.g., "192.168.1.0/24").
func matchIP4(ip net.IP, value string) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false // Not an IPv4 address
	}
	if strings.Contains(value, "/") {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return false
		}
		return network.Contains(ip4)
	}
	target := net.ParseIP(value)
	return target != nil && ip4.Equal(target.To4())
}

// matchIP6 checks if the given IP matches an ip6 mechanism value.
func matchIP6(ip net.IP, value string) bool {
	if strings.Contains(value, "/") {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return false
		}
		return network.Contains(ip)
	}
	target := net.ParseIP(value)
	return target != nil && ip.Equal(target)
}

// matchA checks if the given IP matches any A/AAAA record for the domain.
func matchA(ip net.IP, domain string, resolver Resolver) bool {
	addrs, err := resolver.LookupIPAddr(domain)
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if ip.Equal(addr) {
			return true
		}
	}
	return false
}

// matchMX checks if the given IP matches any MX host's A/AAAA records.
func matchMX(ip net.IP, domain string, resolver Resolver) bool {
	mxRecords, err := resolver.LookupMX(domain)
	if err != nil {
		return false
	}
	for _, mx := range mxRecords {
		host := strings.TrimSuffix(mx.Host, ".")
		if matchA(ip, host, resolver) {
			return true
		}
	}
	return false
}
