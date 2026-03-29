package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestIPRedaction(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, slog.LevelInfo, false)

	logger.Info("connection from 192.168.1.100:25565")
	output := buf.String()
	if strings.Contains(output, "192.168.1.100") {
		t.Errorf("IPv4 address was not redacted: %s", output)
	}
	if !strings.Contains(output, redacted) {
		t.Errorf("expected redacted marker in output: %s", output)
	}
}

func TestIPRedactionDisabled(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, slog.LevelInfo, true)

	logger.Info("connection from 192.168.1.100:25565")
	output := buf.String()
	if !strings.Contains(output, "192.168.1.100") {
		t.Errorf("IPv4 address should not be redacted when logIPs=true: %s", output)
	}
}

func TestSensitiveKeyRedaction(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, slog.LevelInfo, false)

	logger.Info("auth attempt", "password", "supersecret123", "user", "alice")
	output := buf.String()
	if strings.Contains(output, "supersecret123") {
		t.Errorf("password was not redacted: %s", output)
	}
	if !strings.Contains(output, "alice") {
		t.Errorf("non-sensitive field was wrongly redacted: %s", output)
	}
}

func TestIPAttrRedaction(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, slog.LevelInfo, false)

	logger.Info("new session", "remote_addr", "10.0.0.1:443", "user", "bob")
	output := buf.String()
	if strings.Contains(output, "10.0.0.1") {
		t.Errorf("remote_addr was not redacted: %s", output)
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"unknown", slog.LevelInfo},
		{"DEBUG", slog.LevelDebug},
	}
	for _, tt := range tests {
		if got := ParseLevel(tt.input); got != tt.expected {
			t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}
