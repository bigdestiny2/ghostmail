// Package ratelimit provides IP-based rate limiting for GhostMail services.
// Uses a token bucket algorithm with automatic cleanup of stale entries.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter tracks request rates per IP address.
type Limiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     int           // tokens added per interval
	burst    int           // max tokens (bucket capacity)
	interval time.Duration // token refill interval
	cleanup  time.Duration // how often to prune stale entries
}

type bucket struct {
	tokens    float64
	lastCheck time.Time
}

// New creates a new rate limiter.
// rate: requests allowed per interval. burst: max burst size. interval: refill period.
func New(rate, burst int, interval time.Duration) *Limiter {
	l := &Limiter{
		buckets:  make(map[string]*bucket),
		rate:     rate,
		burst:    burst,
		interval: interval,
		cleanup:  5 * time.Minute,
	}
	go l.cleanupLoop()
	return l
}

// Allow checks if a request from the given key (typically IP) should be allowed.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(l.burst), lastCheck: now}
		l.buckets[key] = b
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastCheck)
	b.tokens += elapsed.Seconds() / l.interval.Seconds() * float64(l.rate)
	if b.tokens > float64(l.burst) {
		b.tokens = float64(l.burst)
	}
	b.lastCheck = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// Reset removes rate limit state for a key.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	delete(l.buckets, key)
	l.mu.Unlock()
}

// cleanupLoop periodically removes stale entries to prevent memory leaks.
func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(l.cleanup)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.Lock()
		cutoff := time.Now().Add(-10 * time.Minute)
		for key, b := range l.buckets {
			if b.lastCheck.Before(cutoff) {
				delete(l.buckets, key)
			}
		}
		l.mu.Unlock()
	}
}

// --- Preset limiters for GhostMail services ---

// NewSMTPLimiter returns a limiter for SMTP connections: 30 connections/minute per IP, burst of 10.
func NewSMTPLimiter() *Limiter {
	return New(30, 10, time.Minute)
}

// NewIMAPLimiter returns a limiter for IMAP connections: 60 connections/minute per IP, burst of 20.
func NewIMAPLimiter() *Limiter {
	return New(60, 20, time.Minute)
}

// NewAuthLimiter returns a limiter for login attempts: 5 attempts/minute per IP, burst of 5.
func NewAuthLimiter() *Limiter {
	return New(5, 5, time.Minute)
}

// NewAdminLimiter returns a limiter for admin panel: 30 requests/minute per IP, burst of 15.
func NewAdminLimiter() *Limiter {
	return New(30, 15, time.Minute)
}
