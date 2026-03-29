package dkim

import (
	"bytes"
	"fmt"
	"strings"
)

// AuthResult represents the outcome of email authentication checks.
type AuthResult struct {
	DKIM   string // "pass", "fail", "none"
	SPF    string // "pass", "fail", "none" (placeholder for future SPF check)
	DMARC  string // "pass", "fail", "none" (placeholder for future DMARC check)
	Domain string // domain from DKIM verification
}

// VerifyInbound runs DKIM verification on an inbound message and returns
// the authentication result. SPF/DMARC are placeholders for Phase 4b
// (they require DNS lookups during SMTP session, not at message level).
func VerifyInbound(message []byte) *AuthResult {
	result := &AuthResult{
		DKIM:  "none",
		SPF:   "none",
		DMARC: "none",
	}

	verifications, err := VerifyMessage(message)
	if err != nil || len(verifications) == 0 {
		return result
	}

	// Check the first (primary) DKIM signature
	v := verifications[0]
	result.Domain = v.Domain
	if v.Err == nil {
		result.DKIM = "pass"
	} else {
		result.DKIM = "fail"
	}

	return result
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
		parts = append(parts, fmt.Sprintf("spf=%s", auth.SPF))
	}

	if auth.DMARC != "none" {
		parts = append(parts, fmt.Sprintf("dmarc=%s", auth.DMARC))
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
