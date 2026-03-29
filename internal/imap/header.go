package imap

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/emersion/go-message/textproto"
)

// parseMessageHeader parses the header portion of a raw RFC 5322 message
// and returns a go-message textproto.Header suitable for ExtractEnvelope.
func parseMessageHeader(data []byte) textproto.Header {
	// Find the header/body separator
	idx := bytes.Index(data, []byte("\r\n\r\n"))
	if idx == -1 {
		idx = bytes.Index(data, []byte("\n\n"))
	}
	if idx == -1 {
		idx = len(data)
	}

	headerBytes := data[:idx]

	// Ensure proper line endings
	if !bytes.HasSuffix(headerBytes, []byte("\r\n")) {
		headerBytes = append(headerBytes, '\r', '\n')
	}
	// Add blank line to terminate headers
	headerBytes = append(headerBytes, '\r', '\n')

	h, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(headerBytes)))
	if err != nil {
		return textproto.Header{}
	}
	return h
}

// getHeaderValue retrieves a single header value by key from raw message bytes.
func getHeaderValue(data []byte, key string) string {
	h := parseMessageHeader(data)
	return h.Get(key)
}

// headerContainsValue checks if a header contains a specific substring.
func headerContainsValue(data []byte, key, value string) bool {
	headerValue := getHeaderValue(data, key)
	if value == "" {
		return headerValue != ""
	}
	return strings.Contains(strings.ToLower(headerValue), strings.ToLower(value))
}
