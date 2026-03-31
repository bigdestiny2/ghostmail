// Package vault manages zero-knowledge vault sessions.
// A vault session holds decrypted private keys in RAM, gated by a separate
// vault password that is independent of the IMAP/SMTP auth password.
package vault

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ghostmail/ghostmail/internal/crypto"
	"github.com/ghostmail/ghostmail/internal/storage"
)

// Session represents an active vault unlock with decrypted keys in memory.
type Session struct {
	UserID    int64
	Token     string
	Keys      *crypto.SessionKeys
	ExpiresAt time.Time
}

// Store manages vault sessions: token-to-keys mapping with TTL expiration.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session // token -> session
	byUser   map[int64]*Session  // userID -> active session

	db        *storage.DB
	cryptoSvc *crypto.Service
	logger    *slog.Logger
	ttl       time.Duration
}

// NewStore creates a new vault session store.
func NewStore(db *storage.DB, cryptoSvc *crypto.Service, logger *slog.Logger, ttl time.Duration) *Store {
	return &Store{
		sessions:  make(map[string]*Session),
		byUser:    make(map[int64]*Session),
		db:        db,
		cryptoSvc: cryptoSvc,
		logger:    logger,
		ttl:       ttl,
	}
}

// Unlock verifies the vault password, derives decryption keys, and creates a vault session.
// Returns the session token.
func (s *Store) Unlock(userID int64, vaultPassword []byte) (string, time.Time, error) {
	user, err := s.db.GetUserByID(userID)
	if err != nil || user == nil {
		return "", time.Time{}, fmt.Errorf("user not found")
	}

	if !user.IsVaultUser() {
		return "", time.Time{}, fmt.Errorf("user does not have vault enabled")
	}

	// Decode vault hash
	vaultHash, err := hex.DecodeString(user.VaultHash)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("invalid vault hash")
	}

	// Derive keys from vault password
	keys, err := s.cryptoSvc.UnlockVault(
		vaultPassword, user.VaultKeyParams,
		vaultHash, user.VaultWrappedPrivKey, user.VaultKeyNonce,
	)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("vault unlock failed: %w", err)
	}

	// Generate secure token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		keys.Release()
		return "", time.Time{}, fmt.Errorf("generating token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	expiresAt := time.Now().Add(s.ttl)

	sess := &Session{
		UserID:    userID,
		Token:     token,
		Keys:      keys,
		ExpiresAt: expiresAt,
	}

	s.mu.Lock()
	// Revoke any existing session for this user
	if old, ok := s.byUser[userID]; ok {
		old.Keys.Release()
		delete(s.sessions, old.Token)
	}
	s.sessions[token] = sess
	s.byUser[userID] = sess
	s.mu.Unlock()

	// Persist token to DB for cross-process awareness
	s.db.Exec(`INSERT INTO vault_sessions (user_id, token, created_at, expires_at)
		VALUES (?, ?, ?, ?)`, userID, token, time.Now().Unix(), expiresAt.Unix())

	s.logger.Info("vault unlocked", "user_id", userID, "expires", expiresAt.Format(time.RFC3339))
	return token, expiresAt, nil
}

// Lock revokes a vault session by token, wiping keys from memory.
func (s *Store) Lock(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[token]
	if !ok {
		return
	}

	sess.Keys.Release()
	delete(s.sessions, token)
	delete(s.byUser, sess.UserID)

	// Remove from DB
	s.db.Exec(`DELETE FROM vault_sessions WHERE token = ?`, token)

	s.logger.Info("vault locked", "user_id", sess.UserID)
}

// LockUser revokes any active vault session for the given user.
func (s *Store) LockUser(userID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.byUser[userID]
	if !ok {
		return
	}

	sess.Keys.Release()
	delete(s.sessions, sess.Token)
	delete(s.byUser, userID)

	s.db.Exec(`DELETE FROM vault_sessions WHERE user_id = ?`, userID)
}

// Get returns a vault session by token, or nil if not found/expired.
func (s *Store) Get(token string) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sess, ok := s.sessions[token]
	if !ok || time.Now().After(sess.ExpiresAt) {
		return nil
	}
	return sess
}

// GetByUser returns the active vault session for a user, or nil if locked.
func (s *Store) GetByUser(userID int64) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sess, ok := s.byUser[userID]
	if !ok || time.Now().After(sess.ExpiresAt) {
		return nil
	}
	return sess
}

// IsUnlocked returns true if the user has an active (non-expired) vault session.
func (s *Store) IsUnlocked(userID int64) bool {
	return s.GetByUser(userID) != nil
}

// RunSweeper periodically removes expired vault sessions.
func (s *Store) RunSweeper(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.releaseAll()
			return
		case <-ticker.C:
			s.sweep()
		}
	}
}

func (s *Store) sweep() {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	for token, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			sess.Keys.Release()
			delete(s.sessions, token)
			delete(s.byUser, sess.UserID)
			s.logger.Info("vault session expired", "user_id", sess.UserID)
		}
	}

	// Clean DB
	s.db.Exec(`DELETE FROM vault_sessions WHERE expires_at < ?`, now.Unix())
}

func (s *Store) releaseAll() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, sess := range s.sessions {
		sess.Keys.Release()
	}
	s.sessions = make(map[string]*Session)
	s.byUser = make(map[int64]*Session)
}
