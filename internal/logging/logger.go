// Package logging provides a privacy-respecting structured logger that
// automatically redacts IP addresses and sensitive data from log output.
package logging

import (
	"context"
	"io"
	"log/slog"
	"regexp"
	"strings"
)

var (
	// Match IPv4 addresses
	ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// Match IPv6 addresses (simplified: colon-separated hex groups)
	ipv6Re = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b`)
	// Match email content that might leak into logs
	emailContentRe = regexp.MustCompile(`(?i)(subject|body|content):\s*\S+`)
)

const redacted = "[redacted]"

// PrivacyHandler wraps a slog.Handler to redact sensitive information.
type PrivacyHandler struct {
	inner  slog.Handler
	logIPs bool
}

// NewLogger creates a new privacy-respecting logger.
func NewLogger(w io.Writer, level slog.Level, logIPs bool) *slog.Logger {
	inner := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: level,
	})
	return slog.New(&PrivacyHandler{inner: inner, logIPs: logIPs})
}

// ParseLevel converts a string level name to slog.Level.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func (h *PrivacyHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *PrivacyHandler) Handle(ctx context.Context, r slog.Record) error {
	// Redact the message itself
	r.Message = h.sanitize(r.Message)

	// Redact attribute values
	sanitized := make([]slog.Attr, 0, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		sanitized = append(sanitized, h.sanitizeAttr(a))
		return true
	})

	// Create a new record with sanitized attributes
	newRecord := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	newRecord.AddAttrs(sanitized...)

	return h.inner.Handle(ctx, newRecord)
}

func (h *PrivacyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	sanitized := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		sanitized[i] = h.sanitizeAttr(a)
	}
	return &PrivacyHandler{inner: h.inner.WithAttrs(sanitized), logIPs: h.logIPs}
}

func (h *PrivacyHandler) WithGroup(name string) slog.Handler {
	return &PrivacyHandler{inner: h.inner.WithGroup(name), logIPs: h.logIPs}
}

func (h *PrivacyHandler) sanitize(s string) string {
	if !h.logIPs {
		s = ipv4Re.ReplaceAllString(s, redacted)
		s = ipv6Re.ReplaceAllString(s, redacted)
	}
	s = emailContentRe.ReplaceAllString(s, redacted)
	return s
}

func (h *PrivacyHandler) sanitizeAttr(a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindString {
		a.Value = slog.StringValue(h.sanitize(a.Value.String()))
	}

	// Always redact known-sensitive keys entirely
	key := strings.ToLower(a.Key)
	if key == "password" || key == "secret" || key == "token" || key == "key" || key == "private_key" {
		a.Value = slog.StringValue(redacted)
	}

	// Redact IP-specific keys if IP logging is disabled
	if !h.logIPs && (key == "ip" || key == "remote_addr" || key == "client_ip" || key == "source_ip") {
		a.Value = slog.StringValue(redacted)
	}

	return a
}
