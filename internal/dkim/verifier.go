package dkim

import (
	"bytes"
	"fmt"
	"net"
	"strings"

	"github.com/ghostmail/ghostmail/internal/dmarc"
	"github.com/ghostmail/ghostmail/internal/spf"
)

// AuthResult represents the outcome of email authentication checks.
type AuthResult struct {
	DKIM        string // "pass", "fail", "none"
	SPF         string // "pass", "fail", "softfail", "neutral", "none", "temperror"
	DMARC       string // "pass", "fail", "none"
	DMARCPolicy string // "none", "quarantine", "reject" (the published policy)
	Domain      string // domain from DKIM verification
	FromDomain  string // domain from RFC5322 From header
}

// VerifyInbound runs DKIM, SPF, and DMARC verification on an inbound message.
// connectingIP is the remote IP of the sending MTA, mailFrom is the envelope
// sender (MAIL FROM). Returns the combined authentication result.
func VerifyInbound(message []byte, connectingIP net.IP, mailFrom string) *AuthResult {
	result := &AuthResult{
		DKIM:        "none",
		SPF:         "none",
		DMARC:       "none",
		DMARCPolicy: "none",
	}

	// --- DKIM verification ---
	var dkimDomain string
	verifications, err := VerifyMessage(message)
	if err == nil && len(verifications) > 0 {
		v := verifications[0]
		result.Domain = v.Domain
		dkimDomain = v.Domain
		if v.Err == nil {
			result.DKIM = "pass"
		} else {
			result.DKIM = "fail"
		}
	}

	// --- SPF verification ---
	mailFromDomain := domainFromAddr(mailFrom)
	if connectingIP != nil && mailFromDomain != "" {
		result.SPF = spf.Check(connectingIP, mailFromDomain)
	}

	// --- Extract RFC5322 From domain for DMARC ---
	fromDomain := extractFromDomain(message)
	result.FromDomain = fromDomain

	// --- DMARC verification ---
	if fromDomain != "" {
		dmarcResult := dmarc.Check(fromDomain, result.SPF, mailFromDomain, result.DKIM, dkimDomain)
		result.DMARCPolicy = dmarcResult.Policy
		if !dmarcResult.HasRecord {
			result.DMARC = "none"
		} else if dmarcResult.Pass {
			result.DMARC = "pass"
		} else {
			result.DMARC = "fail"
		}
	}

	return result
}

// domainFromAddr extracts the domain portion from an email address.
// Handles both "user@example.com" and "<user@example.com>" formats.
func domainFromAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimPrefix(addr, "<")
	addr = strings.TrimSuffix(addr, ">")
	parts := strings.SplitN(addr, "@", 2)
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(parts[1])
}

// extractFromDomain parses the RFC5322 From header from raw message bytes
// and returns the domain portion.
func extractFromDomain(message []byte) string {
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(message, sep)
	if idx == -1 {
		sep = []byte("\n\n")
		idx = bytes.Index(message, sep)
	}
	if idx == -1 {
		return ""
	}

	headerPart := string(message[:idx])
	lines := strings.Split(headerPart, "\n")

	var fromValue string
	inFrom := false
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if inFrom {
			// Continuation line (starts with whitespace)
			if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
				fromValue += " " + strings.TrimSpace(line)
				continue
			}
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "from:") {
			fromValue = strings.TrimSpace(line[5:])
			inFrom = true
		}
	}

	if fromValue == "" {
		return ""
	}

	// Extract the email address from the From header value.
	// Handle formats like: "Name <user@domain.com>" or "user@domain.com"
	if idx := strings.LastIndex(fromValue, "<"); idx >= 0 {
		end := strings.Index(fromValue[idx:], ">")
		if end > 0 {
			fromValue = fromValue[idx+1 : idx+end]
		}
	}

	return domainFromAddr(fromValue)
}

// AddAuthResultsHeader prepends an Authentication-Results header to a message.
func AddAuthResultsHeader(message []byte, hostname string, auth *AuthResult) []byte {
	header := FormatAuthResultsHeader(hostname, auth)

	// Find the start of the message (before existing headers)
	return append([]byte(header+"\r\n"), message...)
}

// FormatAuthResultsHeader creates an Authentication-Results header value.
func FormatAuthResultsHeader(hostname string, auth *AuthResult) string {
	var parts []string

	if auth.DKIM != "none" {
		dkimResult := fmt.Sprintf("dkim=%s", auth.DKIM)
		if auth.Domain != "" {
			dkimResult += fmt.Sprintf(" header.d=%s", auth.Domain)
		}
		parts = append(parts, dkimResult)
	}

	if auth.SPF != "none" {
		spfPart := fmt.Sprintf("spf=%s", auth.SPF)
		if auth.FromDomain != "" {
			spfPart += fmt.Sprintf(" smtp.mailfrom=%s", auth.FromDomain)
		}
		parts = append(parts, spfPart)
	}

	if auth.DMARC != "none" {
		dmarcPart := fmt.Sprintf("dmarc=%s", auth.DMARC)
		if auth.DMARCPolicy != "" && auth.DMARCPolicy != "none" {
			dmarcPart += fmt.Sprintf(" (p=%s)", auth.DMARCPolicy)
		}
		if auth.FromDomain != "" {
			dmarcPart += fmt.Sprintf(" header.from=%s", auth.FromDomain)
		}
		parts = append(parts, dmarcPart)
	}

	if len(parts) == 0 {
		parts = append(parts, "none")
	}

	return fmt.Sprintf("Authentication-Results: %s; %s", hostname, strings.Join(parts, "; "))
}

// StripExistingAuthResults removes any existing Authentication-Results
// headers from a message to prevent spoofing.
func StripExistingAuthResults(message []byte) []byte {
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(message, sep)
	if idx == -1 {
		sep = []byte("\n\n")
		idx = bytes.Index(message, sep)
	}
	if idx == -1 {
		return message
	}

	headerPart := message[:idx]
	body := message[idx:]

	lines := splitFoldedHeaders(headerPart)
	var kept []string
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "authentication-results:") {
			continue
		}
		kept = append(kept, line)
	}

	newHeaders := strings.Join(kept, "\r\n")
	return append([]byte(newHeaders), body...)
}

// splitFoldedHeaders splits raw headers respecting folded (continuation) lines.
func splitFoldedHeaders(data []byte) []string {
	rawLines := strings.Split(string(data), "\n")
	var result []string
	var current string

	for _, line := range rawLines {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			current += "\r\n" + line
			continue
		}
		if current != "" {
			result = append(result, current)
		}
		current = line
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}
