package webmail

import (
	"strings"
	"testing"
)

func TestDecodeMIMEBodyBase64(t *testing.T) {
	// Simulate a multipart message with base64-encoded text
	boundary := "===============1234567890=="
	body := "--" + boundary + "\r\n" +
		"Content-Type: text/plain; charset=\"utf-8\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		"SGVsbG8gV29ybGQ=\r\n" + // "Hello World"
		"\r\n" +
		"--" + boundary + "--\r\n"

	contentType := "multipart/mixed; boundary=\"" + boundary + "\""

	text, html := decodeMIMEBody([]byte(body), contentType)
	if text != "Hello World" {
		t.Errorf("expected 'Hello World', got %q", text)
	}
	if html != "" {
		t.Errorf("expected no HTML, got %q", html)
	}
}

func TestDecodeMIMEBodyPlainText(t *testing.T) {
	body := []byte("Just plain text here")
	text, html := decodeMIMEBody(body, "text/plain; charset=utf-8")
	if text != "Just plain text here" {
		t.Errorf("expected plain text, got %q", text)
	}
	if html != "" {
		t.Errorf("expected no HTML, got %q", html)
	}
}

func TestDecodeMIMEBodyHTML(t *testing.T) {
	body := []byte("<h1>Hello</h1>")
	text, html := decodeMIMEBody(body, "text/html; charset=utf-8")
	if text != "" {
		t.Errorf("expected no text, got %q", text)
	}
	if html != "<h1>Hello</h1>" {
		t.Errorf("expected HTML, got %q", html)
	}
}

func TestDecodeMIMEBodyNoContentType(t *testing.T) {
	body := []byte("No content type")
	text, html := decodeMIMEBody(body, "")
	if text != "No content type" {
		t.Errorf("expected text fallback, got %q", text)
	}
	if html != "" {
		t.Errorf("expected no HTML, got %q", html)
	}
}

func TestDecodeTransferEncodingBase64(t *testing.T) {
	encoded := []byte("SGVsbG8gV29ybGQ=")
	result := decodeTransferEncoding(encoded, "base64")
	if result != "Hello World" {
		t.Errorf("expected 'Hello World', got %q", result)
	}
}

func TestDecodeTransferEncodingBase64WithLineBreaks(t *testing.T) {
	// Base64 often has line breaks
	encoded := []byte("SGVs\r\nbG8g\r\nV29y\r\nbGQ=")
	result := decodeTransferEncoding(encoded, "base64")
	if result != "Hello World" {
		t.Errorf("expected 'Hello World', got %q", result)
	}
}

func TestDecodeTransferEncodingQP(t *testing.T) {
	encoded := []byte("Hello=20World=21")
	result := decodeTransferEncoding([]byte(encoded), "quoted-printable")
	if result != "Hello World!" {
		t.Errorf("expected 'Hello World!', got %q", result)
	}
}

func TestDecodeTransferEncodingNone(t *testing.T) {
	result := decodeTransferEncoding([]byte("plain text"), "")
	if result != "plain text" {
		t.Errorf("expected passthrough, got %q", result)
	}
}

func TestExtractTopLevelEncoding(t *testing.T) {
	header := []byte("Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n")
	enc := extractTopLevelEncoding(header)
	if enc != "base64" {
		t.Errorf("expected 'base64', got %q", enc)
	}

	header2 := []byte("Content-Type: text/plain\r\n")
	enc2 := extractTopLevelEncoding(header2)
	if enc2 != "" {
		t.Errorf("expected empty, got %q", enc2)
	}
}

func TestDecodeMIMEMultipartAlternative(t *testing.T) {
	boundary := "abc123"
	body := "--" + boundary + "\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Plain version\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<b>HTML version</b>\r\n" +
		"--" + boundary + "--\r\n"

	contentType := "multipart/alternative; boundary=" + boundary

	text, html := decodeMIMEBody([]byte(body), contentType)
	if !strings.Contains(text, "Plain version") {
		t.Errorf("expected plain text part, got %q", text)
	}
	if !strings.Contains(html, "HTML version") {
		t.Errorf("expected HTML part, got %q", html)
	}
}
