package ratelimit

import (
	"testing"
	"time"
)

func TestBasicAllow(t *testing.T) {
	l := New(10, 5, time.Second)

	// First 5 should pass (burst)
	for i := 0; i < 5; i++ {
		if !l.Allow("1.2.3.4") {
			t.Errorf("request %d should be allowed (within burst)", i)
		}
	}

	// 6th should be denied (burst exhausted, no time to refill)
	if l.Allow("1.2.3.4") {
		t.Error("request 6 should be denied (burst exhausted)")
	}
}

func TestDifferentKeys(t *testing.T) {
	l := New(10, 2, time.Second)

	l.Allow("ip-a")
	l.Allow("ip-a")

	// ip-a exhausted, ip-b should still work
	if !l.Allow("ip-b") {
		t.Error("different IP should have its own bucket")
	}
}

func TestRefill(t *testing.T) {
	l := New(100, 1, time.Second) // 100/sec, burst 1

	l.Allow("x") // consume the burst token
	if l.Allow("x") {
		t.Error("should be denied immediately after burst")
	}

	time.Sleep(15 * time.Millisecond) // wait for ~1.5 tokens to refill
	if !l.Allow("x") {
		t.Error("should be allowed after refill")
	}
}

func TestReset(t *testing.T) {
	l := New(1, 1, time.Minute)

	l.Allow("y") // exhaust
	if l.Allow("y") {
		t.Error("should be denied")
	}

	l.Reset("y")
	if !l.Allow("y") {
		t.Error("should be allowed after reset")
	}
}

func TestPresets(t *testing.T) {
	smtp := NewSMTPLimiter()
	imap := NewIMAPLimiter()
	auth := NewAuthLimiter()
	admin := NewAdminLimiter()

	// All should allow first request
	if !smtp.Allow("test") {
		t.Error("SMTP limiter should allow")
	}
	if !imap.Allow("test") {
		t.Error("IMAP limiter should allow")
	}
	if !auth.Allow("test") {
		t.Error("Auth limiter should allow")
	}
	if !admin.Allow("test") {
		t.Error("Admin limiter should allow")
	}
}

func TestAuthLimiterStrictness(t *testing.T) {
	l := NewAuthLimiter() // 5/min, burst 5

	// Exhaust all 5 attempts
	for i := 0; i < 5; i++ {
		if !l.Allow("attacker") {
			t.Fatalf("attempt %d should be allowed", i)
		}
	}

	// 6th should be blocked
	if l.Allow("attacker") {
		t.Error("6th auth attempt should be blocked")
	}
}
