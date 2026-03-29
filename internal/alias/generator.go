// Package alias provides disposable email alias generation and routing.
package alias

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
	"time"

	"github.com/ghostmail/ghostmail/internal/storage"
)

// Generator creates and manages disposable aliases.
type Generator struct {
	db         *storage.DB
	maxPerUser int
}

// NewGenerator creates a new alias generator.
func NewGenerator(db *storage.DB, maxPerUser int) *Generator {
	return &Generator{db: db, maxPerUser: maxPerUser}
}

// Create generates a new random alias for a user.
func (g *Generator) Create(userID int64, domain, description string, ttl time.Duration, maxMessages int) (*storage.Alias, error) {
	// Check alias limit
	existing, err := g.db.ListAliases(userID)
	if err != nil {
		return nil, fmt.Errorf("checking alias count: %w", err)
	}
	if len(existing) >= g.maxPerUser {
		return nil, fmt.Errorf("alias limit reached (%d/%d)", len(existing), g.maxPerUser)
	}

	address := generateAddress(domain)

	a := &storage.Alias{
		UserID:      userID,
		Address:     address,
		Domain:      domain,
		Description: description,
		IsActive:    true,
	}

	if ttl > 0 {
		exp := time.Now().Add(ttl)
		a.ExpiresAt = &exp
	}

	if maxMessages > 0 {
		a.MaxMessages = &maxMessages
	}

	if err := g.db.CreateAlias(a); err != nil {
		return nil, fmt.Errorf("creating alias: %w", err)
	}

	return a, nil
}

// Resolve resolves an email address to its owner, handling alias validation.
// Returns the user, whether it was an alias, and any error.
func (g *Generator) Resolve(address string) (user *storage.User, isAlias bool, err error) {
	parts := strings.SplitN(address, "@", 2)
	if len(parts) != 2 {
		return nil, false, fmt.Errorf("invalid address: %s", address)
	}

	// Try direct user lookup
	user, err = g.db.GetUser(parts[0], parts[1])
	if err != nil {
		return nil, false, err
	}
	if user != nil {
		return user, false, nil
	}

	// Try alias resolution
	alias, err := g.db.ResolveAlias(address)
	if err != nil {
		return nil, false, err
	}
	if alias == nil {
		return nil, false, nil
	}

	// Validate alias state
	if !alias.IsActive {
		return nil, true, fmt.Errorf("alias inactive")
	}
	if alias.ExpiresAt != nil && alias.ExpiresAt.Before(time.Now()) {
		g.db.DeactivateAlias(alias.ID)
		return nil, true, fmt.Errorf("alias expired")
	}
	if alias.MaxMessages != nil && alias.MessageCount >= *alias.MaxMessages {
		g.db.DeactivateAlias(alias.ID)
		return nil, true, fmt.Errorf("alias message limit reached")
	}

	// Increment counter
	g.db.IncrementAliasCount(alias.ID)

	// Look up the alias owner
	user, err = g.db.GetUserByID(alias.UserID)
	if err != nil || user == nil {
		return nil, true, fmt.Errorf("alias owner not found")
	}

	return user, true, nil
}

// generateAddress creates a random alias address.
func generateAddress(domain string) string {
	b := make([]byte, 8)
	rand.Read(b)
	// Base32 without padding, lowercase, 13 chars
	encoded := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
	if len(encoded) > 12 {
		encoded = encoded[:12]
	}
	return encoded + "@" + domain
}

// GenerateCustom creates an alias with a user-specified local part.
func (g *Generator) GenerateCustom(userID int64, localPart, domain, description string) (*storage.Alias, error) {
	existing, err := g.db.ListAliases(userID)
	if err != nil {
		return nil, err
	}
	if len(existing) >= g.maxPerUser {
		return nil, fmt.Errorf("alias limit reached (%d/%d)", len(existing), g.maxPerUser)
	}

	a := &storage.Alias{
		UserID:      userID,
		Address:     localPart + "@" + domain,
		Domain:      domain,
		Description: description,
		IsActive:    true,
	}

	if err := g.db.CreateAlias(a); err != nil {
		return nil, fmt.Errorf("creating alias: %w", err)
	}

	return a, nil
}
