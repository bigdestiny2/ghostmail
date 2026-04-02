package webmail

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsTorRequest(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"abcdef1234567890.onion", true},
		{"abcdef1234567890.onion:443", true},
		{"abcdef1234567890.onion:80", true},
		{"mail.example.com", false},
		{"mail.example.com:8443", false},
		{"localhost", false},
		{"localhost:8080", false},
		{"127.0.0.1:8443", false},
		{"", false},
	}

	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/mail/login", nil)
		r.Host = tt.host
		got := isTorRequest(r)
		if got != tt.want {
			t.Errorf("isTorRequest(Host=%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestTorGate_Disabled(t *testing.T) {
	// When TorOnly is false, the handler should pass through
	h := &Handler{}
	h.cfg = testConfig(false)

	called := false
	inner := func(w http.ResponseWriter, r *http.Request) { called = true }

	wrapped := h.torGate(inner)

	r := httptest.NewRequest("GET", "/mail/login", nil)
	r.Host = "mail.example.com"
	w := httptest.NewRecorder()
	wrapped(w, r)

	if !called {
		t.Error("handler was not called when TorOnly=false")
	}
}

func TestTorGate_BlocksClearnet(t *testing.T) {
	h := &Handler{}
	h.cfg = testConfig(true)
	h.logger = testLogger()

	called := false
	inner := func(w http.ResponseWriter, r *http.Request) { called = true }

	wrapped := h.torGate(inner)

	r := httptest.NewRequest("GET", "/mail/login", nil)
	r.Host = "mail.example.com"
	w := httptest.NewRecorder()
	wrapped(w, r)

	if called {
		t.Error("handler was called for clearnet request when TorOnly=true")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("got status %d, want 403", w.Code)
	}
	if !containsString(w.Body.String(), "Tor Access Required") {
		t.Error("landing page not returned")
	}
}

func TestTorGate_AllowsOnion(t *testing.T) {
	h := &Handler{}
	h.cfg = testConfig(true)
	h.logger = testLogger()

	called := false
	inner := func(w http.ResponseWriter, r *http.Request) { called = true }

	wrapped := h.torGate(inner)

	r := httptest.NewRequest("GET", "/mail/login", nil)
	r.Host = "abcdef1234567890.onion"
	w := httptest.NewRecorder()
	wrapped(w, r)

	if !called {
		t.Error("handler was not called for .onion request when TorOnly=true")
	}
}

func TestTorGateAPI_BlocksClearnet(t *testing.T) {
	h := &Handler{}
	h.cfg = testConfig(true)
	h.logger = testLogger()

	called := false
	inner := func(w http.ResponseWriter, r *http.Request) { called = true }

	wrapped := h.torGateAPI(inner)

	r := httptest.NewRequest("POST", "/api/v1/search", nil)
	r.Host = "mail.example.com"
	w := httptest.NewRecorder()
	wrapped(w, r)

	if called {
		t.Error("API handler was called for clearnet request")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("got status %d, want 403", w.Code)
	}
	if !containsString(w.Body.String(), "only accessible via Tor") {
		t.Error("expected JSON error about Tor access")
	}
}

func containsString(haystack, needle string) bool {
	return len(haystack) > 0 && len(needle) > 0 && haystack != "" && needle != "" &&
		httpContains(haystack, needle)
}

func httpContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
