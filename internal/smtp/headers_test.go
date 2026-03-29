package smtp

import (
	"strings"
	"testing"
)

func TestStripHeaders(t *testing.T) {
	msg := "Received: from evil.com by server\r\n" +
		"From: alice@example.com\r\n" +
		"To: bob@example.com\r\n" +
		"Subject: Hello\r\n" +
		"X-Mailer: Thunderbird 99\r\n" +
		"X-Originating-IP: 1.2.3.4\r\n" +
		"User-Agent: BadClient/1.0\r\n" +
		"Message-ID: <old@client.local>\r\n" +
		"\r\n" +
		"Body content here"

	cfg := StripConfig{
		StripReceived:      true,
		StripUserAgent:     true,
		StripXOrigIP:       true,
		NormalizeMessageID: true,
	}

	result := string(StripHeaders([]byte(msg), "mail.example.com", cfg))

	if strings.Contains(result, "Received:") {
		t.Error("Received header was not stripped")
	}
	if strings.Contains(result, "X-Mailer:") {
		t.Error("X-Mailer was not stripped")
	}
	if strings.Contains(result, "X-Originating-IP:") {
		t.Error("X-Originating-IP was not stripped")
	}
	if strings.Contains(result, "User-Agent:") {
		t.Error("User-Agent was not stripped")
	}
	if strings.Contains(result, "old@client.local") {
		t.Error("Original Message-ID was not normalized")
	}
	if !strings.Contains(result, "@mail.example.com") {
		t.Error("Message-ID should use server domain")
	}
	if !strings.Contains(result, "From: alice@example.com") {
		t.Error("From header should be preserved")
	}
	if !strings.Contains(result, "Subject: Hello") {
		t.Error("Subject header should be preserved")
	}
	if !strings.Contains(result, "Body content here") {
		t.Error("Body should be preserved")
	}
}

func TestExtractAddr(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"<alice@example.com>", "alice@example.com"},
		{"alice@example.com", "alice@example.com"},
		{" <ALICE@EXAMPLE.COM> ", "alice@example.com"},
	}
	for _, tt := range tests {
		got := extractAddr(tt.input)
		if got != tt.expected {
			t.Errorf("extractAddr(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
