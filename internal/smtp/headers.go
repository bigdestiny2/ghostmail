package smtp

import (
	"bytes"
	"fmt"
	"net/textproto"
	"strings"
)

// StripHeaders removes identifying headers from outbound messages.
// This is a privacy-critical function.
func StripHeaders(data []byte, hostname string, strip StripConfig) []byte {
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		headerEnd = bytes.Index(data, []byte("\n\n"))
		if headerEnd == -1 {
			return data
		}
	}

	headerSection := data[:headerEnd]
	body := data[headerEnd:]

	lines := splitHeaderLines(headerSection)
	var result []string

	for _, line := range lines {
		headerName := extractHeaderName(line)
		if shouldStrip(headerName, strip) {
			continue
		}
		result = append(result, line)
	}

	// Normalize Message-ID if configured
	if strip.NormalizeMessageID {
		normalized := false
		for i, line := range result {
			if strings.HasPrefix(strings.ToLower(line), "message-id:") {
				result[i] = fmt.Sprintf("Message-ID: <%d@%s>", generateID(), hostname)
				normalized = true
				break
			}
		}
		if !normalized {
			result = append(result, fmt.Sprintf("Message-ID: <%d@%s>", generateID(), hostname))
		}
	}

	newHeaders := []byte(strings.Join(result, "\r\n"))
	return append(newHeaders, body...)
}

type StripConfig struct {
	StripReceived      bool
	StripUserAgent     bool
	StripXOrigIP       bool
	NormalizeMessageID bool
}

func shouldStrip(name string, cfg StripConfig) bool {
	lower := strings.ToLower(name)

	if cfg.StripReceived && lower == "received" {
		return true
	}
	if cfg.StripUserAgent && (lower == "user-agent" || lower == "x-mailer") {
		return true
	}
	if cfg.StripXOrigIP && (lower == "x-originating-ip" || lower == "x-forwarded-for") {
		return true
	}

	// Always strip these internal headers
	switch lower {
	case "x-ghostmail-internal", "x-sender-ip":
		return true
	}

	return false
}

func extractHeaderName(line string) string {
	idx := strings.Index(line, ":")
	if idx == -1 {
		return ""
	}
	return textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(line[:idx]))
}

// splitHeaderLines splits raw headers into logical lines (handling folded headers).
func splitHeaderLines(data []byte) []string {
	rawLines := strings.Split(string(data), "\n")
	var result []string
	var current string

	for _, line := range rawLines {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		// Folded header continuation (starts with whitespace)
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

var idCounter uint64

func generateID() uint64 {
	idCounter++
	return idCounter
}
