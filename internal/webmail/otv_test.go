package webmail

import (
	"testing"
	"time"
)

func TestOTVCreateAndView(t *testing.T) {
	store := NewOTVStore()

	msg := &otvMessage{
		From:    "alice@test.com",
		To:      "bob@test.com",
		Subject: "Secret message",
		Date:    "2026-04-01 12:00:00",
		Body:    "This is confidential content.",
	}

	token := store.Create(1, msg)
	if len(token) != 64 {
		t.Fatalf("expected 64-char token, got %d", len(token))
	}

	// View should return the message
	result := store.View(token)
	if result == nil {
		t.Fatal("expected message, got nil")
	}
	if result.Subject != "Secret message" {
		t.Errorf("expected subject 'Secret message', got %q", result.Subject)
	}
	if result.Body != "This is confidential content." {
		t.Errorf("expected body content, got %q", result.Body)
	}

	// Second view should return nil (single use)
	result2 := store.View(token)
	if result2 != nil {
		t.Error("expected nil on second view (single use)")
	}
}

func TestOTVExpiry(t *testing.T) {
	store := NewOTVStore()

	msg := &otvMessage{Subject: "Expires soon"}

	// Manually insert with old timestamp
	store.mu.Lock()
	store.entries["expired-token"] = &otvEntry{
		Message:   msg,
		UserID:    1,
		CreatedAt: time.Now().Add(-10 * time.Minute), // 10 min ago
	}
	store.mu.Unlock()

	// Should return nil (expired)
	result := store.View("expired-token")
	if result != nil {
		t.Error("expected nil for expired token")
	}
}

func TestOTVSweep(t *testing.T) {
	store := NewOTVStore()

	// Add fresh and expired entries
	store.Create(1, &otvMessage{Subject: "Fresh"})

	store.mu.Lock()
	store.entries["old-token"] = &otvEntry{
		Message:   &otvMessage{Subject: "Old"},
		UserID:    1,
		CreatedAt: time.Now().Add(-10 * time.Minute),
	}
	store.mu.Unlock()

	store.Sweep()

	store.mu.Lock()
	count := len(store.entries)
	_, oldExists := store.entries["old-token"]
	store.mu.Unlock()

	if oldExists {
		t.Error("expired entry should have been swept")
	}
	if count != 1 {
		t.Errorf("expected 1 entry after sweep, got %d", count)
	}
}

func TestOTVCountForUser(t *testing.T) {
	store := NewOTVStore()

	store.Create(1, &otvMessage{Subject: "A"})
	store.Create(1, &otvMessage{Subject: "B"})
	store.Create(2, &otvMessage{Subject: "C"})

	if c := store.CountForUser(1); c != 2 {
		t.Errorf("expected 2 for user 1, got %d", c)
	}
	if c := store.CountForUser(2); c != 1 {
		t.Errorf("expected 1 for user 2, got %d", c)
	}
	if c := store.CountForUser(99); c != 0 {
		t.Errorf("expected 0 for user 99, got %d", c)
	}
}

func TestOTVInvalidToken(t *testing.T) {
	store := NewOTVStore()

	result := store.View("nonexistent-token")
	if result != nil {
		t.Error("expected nil for nonexistent token")
	}

	result2 := store.View("")
	if result2 != nil {
		t.Error("expected nil for empty token")
	}
}
