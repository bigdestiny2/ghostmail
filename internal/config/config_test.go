package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()
	if cfg.Server.Hostname != "localhost" {
		t.Errorf("expected default hostname 'localhost', got %q", cfg.Server.Hostname)
	}
	if cfg.SMTP.MaxMessageSize != 26214400 {
		t.Errorf("expected default max_message_size 26214400, got %d", cfg.SMTP.MaxMessageSize)
	}
	if cfg.Crypto.Argon2Memory != 65536 {
		t.Errorf("expected default argon2_memory 65536, got %d", cfg.Crypto.Argon2Memory)
	}
	if !cfg.Privacy.StripReceivedHeaders {
		t.Error("expected strip_received_headers to be true by default")
	}
}

func TestLoad(t *testing.T) {
	content := `
[server]
hostname = "mail.example.com"
data_dir = "/tmp/ghostmail-test"
log_level = "debug"

[smtp]
listen_addr = ":2525"
max_message_size = 10485760

[imap]
listen_addr = ":1993"
idle_timeout = "15m"

[crypto]
argon2_time = 4
argon2_memory = 131072
argon2_threads = 8
session_key_ttl = "1h"

[expiry]
trash_ttl = "7d"
sweep_interval = "10m"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "ghostmail.toml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Server.Hostname != "mail.example.com" {
		t.Errorf("expected hostname 'mail.example.com', got %q", cfg.Server.Hostname)
	}
	if cfg.SMTP.ListenAddr != ":2525" {
		t.Errorf("expected smtp addr ':2525', got %q", cfg.SMTP.ListenAddr)
	}
	if cfg.SMTP.MaxMessageSize != 10485760 {
		t.Errorf("expected max_message_size 10485760, got %d", cfg.SMTP.MaxMessageSize)
	}
	if cfg.Crypto.Argon2Memory != 131072 {
		t.Errorf("expected argon2_memory 131072, got %d", cfg.Crypto.Argon2Memory)
	}
	// Defaults should be preserved for unset fields
	if !cfg.Privacy.StripReceivedHeaders {
		t.Error("expected strip_received_headers default to be preserved")
	}
	if cfg.DKIM.Selector != "ghostmail" {
		t.Errorf("expected dkim selector 'ghostmail', got %q", cfg.DKIM.Selector)
	}
}

func TestValidation(t *testing.T) {
	cfg := Defaults()
	cfg.Server.Hostname = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected validation error for empty hostname")
	}

	cfg = Defaults()
	cfg.Server.LogLevel = "invalid"
	if err := cfg.Validate(); err == nil {
		t.Error("expected validation error for invalid log_level")
	}

	cfg = Defaults()
	cfg.SMTP.MaxMessageSize = -1
	if err := cfg.Validate(); err == nil {
		t.Error("expected validation error for negative max_message_size")
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"5m", 5 * time.Minute, false},
		{"1h", time.Hour, false},
		{"30d", 30 * 24 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"500ms", 500 * time.Millisecond, false},
		{"bad", 0, true},
	}

	for _, tt := range tests {
		d, err := ParseDuration(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseDuration(%q): expected error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseDuration(%q): unexpected error: %v", tt.input, err)
			continue
		}
		if d != tt.expected {
			t.Errorf("ParseDuration(%q) = %v, want %v", tt.input, d, tt.expected)
		}
	}
}

func TestEnvOverrides(t *testing.T) {
	content := `
[server]
hostname = "original.com"
data_dir = "/tmp/test"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "ghostmail.toml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GHOSTMAIL_HOSTNAME", "override.com")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Hostname != "override.com" {
		t.Errorf("expected overridden hostname 'override.com', got %q", cfg.Server.Hostname)
	}
}
