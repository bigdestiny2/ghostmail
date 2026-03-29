package webmail

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/ghostmail/ghostmail/internal/crypto"
)

const (
	sessionTTL    = 4 * time.Hour
	sessionCookie = "ghostmail_session"
	sweepInterval = 5 * time.Minute
)

// WebSession holds an authenticated user's session including decrypted crypto keys.
type WebSession struct {
	UserID    int64
	Username  string
	Domain    string
	IsAdmin   bool
	Keys      *crypto.SessionKeys
	CreatedAt time.Time
}

// SessionStore manages webmail sessions with crypto key lifecycle.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*WebSession
	logger   *slog.Logger
}

func NewSessionStore(logger *slog.Logger) *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*WebSession),
		logger:   logger,
	}
}

// StartSweeper launches a background goroutine that cleans expired sessions.
func (ss *SessionStore) StartSweeper(stop <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ss.sweepExpired()
			case <-stop:
				return
			}
		}
	}()
}

func (ss *SessionStore) sweepExpired() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	now := time.Now()
	for token, sess := range ss.sessions {
		if now.Sub(sess.CreatedAt) > sessionTTL {
			if sess.Keys != nil {
				sess.Keys.Release()
			}
			delete(ss.sessions, token)
			ss.logger.Debug("webmail session expired", "user", sess.Username)
		}
	}
}

// Create stores a new session and returns the token.
func (ss *SessionStore) Create(sess *WebSession) string {
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)

	ss.mu.Lock()
	ss.sessions[token] = sess
	ss.mu.Unlock()

	return token
}

// Get retrieves a session by token, returning nil if expired or not found.
func (ss *SessionStore) Get(token string) *WebSession {
	ss.mu.RLock()
	sess, ok := ss.sessions[token]
	ss.mu.RUnlock()

	if !ok || time.Since(sess.CreatedAt) > sessionTTL {
		return nil
	}
	return sess
}

// Delete removes a session and wipes crypto keys.
func (ss *SessionStore) Delete(token string) {
	ss.mu.Lock()
	if sess, ok := ss.sessions[token]; ok {
		if sess.Keys != nil {
			sess.Keys.Release()
		}
		delete(ss.sessions, token)
	}
	ss.mu.Unlock()
}

// GetFromRequest extracts the session from an HTTP request cookie.
func (ss *SessionStore) GetFromRequest(r *http.Request) *WebSession {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	return ss.Get(cookie.Value)
}

// ReleaseAll wipes all sessions (used during shutdown).
func (ss *SessionStore) ReleaseAll() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	for token, sess := range ss.sessions {
		if sess.Keys != nil {
			sess.Keys.Release()
		}
		delete(ss.sessions, token)
	}
}
