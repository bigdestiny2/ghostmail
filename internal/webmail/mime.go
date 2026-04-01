package webmail

import (
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"
)

// decodeMIMEBody takes the raw RFC 5322 body (after headers) and the Content-Type header,
// and returns decoded plain text and HTML parts.
func decodeMIMEBody(body []byte, contentType string) (text, html string) {
	if contentType == "" {
		// No content type — treat as plain text
		return string(body), ""
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return string(body), ""
	}

	// Simple text/plain or text/html (not multipart)
	if strings.HasPrefix(mediaType, "text/") {
		// The body might be in the top-level headers' Content-Transfer-Encoding
		// but since we get just the body after split, handle inline
		decoded := string(body)
		if strings.HasPrefix(mediaType, "text/html") {
			return "", decoded
		}
		return decoded, ""
	}

	// Multipart messages
	if !strings.HasPrefix(mediaType, "multipart/") {
		return string(body), ""
	}

	boundary := params["boundary"]
	if boundary == "" {
		return string(body), ""
	}

	reader := multipart.NewReader(strings.NewReader(string(body)), boundary)
	for {
		part, err := reader.NextPart()
		if err != nil {
			break
		}

		partType := part.Header.Get("Content-Type")
		partEncoding := strings.ToLower(part.Header.Get("Content-Transfer-Encoding"))

		// Read full part body
		partBody, err := io.ReadAll(io.LimitReader(part, 10*1024*1024)) // 10MB max per part
		if err != nil {
			part.Close()
			continue
		}

		// Decode transfer encoding
		decoded := decodeTransferEncoding(partBody, partEncoding)

		partMediaType, partParams, _ := mime.ParseMediaType(partType)

		if strings.HasPrefix(partMediaType, "text/plain") {
			text = decodeCharset(decoded, partParams["charset"])
		} else if strings.HasPrefix(partMediaType, "text/html") {
			html = decodeCharset(decoded, partParams["charset"])
		} else if strings.HasPrefix(partMediaType, "multipart/") {
			// Nested multipart — recurse
			nestedText, nestedHTML := decodeMIMEBody(partBody, partType)
			if text == "" {
				text = nestedText
			}
			if html == "" {
				html = nestedHTML
			}
		}
		part.Close()
	}

	return text, html
}

// decodeTransferEncoding decodes base64 or quoted-printable encoded content.
func decodeTransferEncoding(data []byte, encoding string) string {
	switch encoding {
	case "base64":
		// Strip whitespace from base64
		clean := strings.Map(func(r rune) rune {
			if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, string(data))
		decoded, err := base64.StdEncoding.DecodeString(clean)
		if err != nil {
			// Try with padding fix
			decoded, err = base64.RawStdEncoding.DecodeString(clean)
			if err != nil {
				return string(data)
			}
		}
		return string(decoded)
	case "quoted-printable":
		return decodeQuotedPrintable(string(data))
	default:
		return string(data)
	}
}

// decodeQuotedPrintable decodes QP-encoded content.
func decodeQuotedPrintable(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '=' {
			if i+2 < len(s) {
				if s[i+1] == '\r' && i+2 < len(s) && s[i+2] == '\n' {
					// Soft line break
					i += 3
					continue
				}
				if s[i+1] == '\n' {
					i += 2
					continue
				}
				// Hex pair
				hi := unhex(s[i+1])
				lo := unhex(s[i+2])
				if hi >= 0 && lo >= 0 {
					b.WriteByte(byte(hi<<4 | lo))
					i += 3
					continue
				}
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	}
	return -1
}

// decodeCharset converts charset to UTF-8 (passthrough for utf-8/us-ascii).
func decodeCharset(s string, charset string) string {
	// Most modern email is UTF-8; for now passthrough
	_ = charset
	return s
}

// extractTopLevelEncoding checks if the top-level message has a Content-Transfer-Encoding.
// This is used when the message is not multipart but has base64 encoding.
func extractTopLevelEncoding(headerData []byte) string {
	lines := strings.Split(string(headerData), "\n")
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(strings.ToLower(line), "content-transfer-encoding:") {
			return strings.TrimSpace(strings.ToLower(line[len("content-transfer-encoding:"):]))
		}
	}
	return ""
}

// Ensure textproto is used (suppresses import warning if needed in future).
var _ textproto.MIMEHeader
