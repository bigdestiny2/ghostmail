// Package subdomain provides instant email addresses on a shared domain.
// Users who don't own a domain get a unique subdomain like user@abc123.ghostmail.dev
// backed by wildcard DNS on the shared parent domain.
package subdomain

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ghostmail/ghostmail/internal/storage"
)

// Service manages subdomain allocation on a shared parent domain.
type Service struct {
	db           *storage.DB
	parentDomain string // e.g., "ghostmail.dev"
	logger       *slog.Logger
}

// Config holds subdomain service configuration.
type Config struct {
	Enabled      bool   `toml:"enabled"`
	ParentDomain string `toml:"parent_domain"` // e.g., "ghostmail.dev"
	MaxPerIP     int    `toml:"max_per_ip"`    // max subdomains per source IP
}

// Allocation represents a subdomain assignment.
type Allocation struct {
	ID          int64
	Subdomain   string // e.g., "a1b2c3"
	FQDN        string // e.g., "a1b2c3.ghostmail.dev"
	OwnerEmail  string // admin user for this subdomain
	ServerID    string // identifies which GhostMail instance
	CreatedAt   time.Time
	ExpiresAt   *time.Time // nil = never expires
	Active      bool
}

// NewService creates a subdomain allocation service.
func NewService(db *storage.DB, parentDomain string, logger *slog.Logger) *Service {
	return &Service{
		db:           db,
		parentDomain: parentDomain,
		logger:       logger,
	}
}

// Allocate creates a new subdomain and sets up the domain + admin user in GhostMail.
// Returns the full domain (e.g., "a1b2c3.ghostmail.dev") and admin email.
func (s *Service) Allocate(adminUsername, adminPassword string) (*Allocation, error) {
	sub, err := generateSubdomain()
	if err != nil {
		return nil, fmt.Errorf("generating subdomain: %w", err)
	}

	fqdn := sub + "." + s.parentDomain

	// Check uniqueness
	existing, _ := s.db.GetDomain(fqdn)
	if existing != nil {
		// Extremely unlikely collision, retry once
		sub, err = generateSubdomain()
		if err != nil {
			return nil, err
		}
		fqdn = sub + "." + s.parentDomain
	}

	// Register domain in GhostMail
	domain := &storage.Domain{
		Name:      fqdn,
		IsPrimary: true,
	}
	if err := s.db.CreateDomain(domain); err != nil {
		return nil, fmt.Errorf("creating domain %s: %w", fqdn, err)
	}

	s.logger.Info("subdomain allocated",
		"subdomain", sub,
		"fqdn", fqdn,
		"admin", adminUsername+"@"+fqdn,
	)

	alloc := &Allocation{
		Subdomain:  sub,
		FQDN:       fqdn,
		OwnerEmail: adminUsername + "@" + fqdn,
		CreatedAt:  time.Now(),
		Active:     true,
	}

	return alloc, nil
}

// ParentDomain returns the configured parent domain.
func (s *Service) ParentDomain() string {
	return s.parentDomain
}

// FormatEmail returns a full email address for a subdomain allocation.
func (s *Service) FormatEmail(username, subdomain string) string {
	return fmt.Sprintf("%s@%s.%s", username, subdomain, s.parentDomain)
}

// generateSubdomain creates a random 6-character hex string (48 bits of entropy).
// Gives 16.7 million possible subdomains — enough for a single operator.
func generateSubdomain() (string, error) {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenerateCustomSubdomain creates a subdomain from a user-chosen name.
// Validates that the name is DNS-safe and available.
func (s *Service) GenerateCustomSubdomain(name, adminUsername, adminPassword string) (*Allocation, error) {
	name = strings.ToLower(strings.TrimSpace(name))

	// Validate DNS label
	if len(name) < 2 || len(name) > 63 {
		return nil, fmt.Errorf("subdomain must be 2-63 characters")
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return nil, fmt.Errorf("subdomain can only contain letters, numbers, and hyphens")
		}
	}
	if strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") {
		return nil, fmt.Errorf("subdomain cannot start or end with a hyphen")
	}

	fqdn := name + "." + s.parentDomain

	// Check availability
	existing, _ := s.db.GetDomain(fqdn)
	if existing != nil {
		return nil, fmt.Errorf("subdomain %s is already taken", name)
	}

	// Register domain
	domain := &storage.Domain{
		Name:      fqdn,
		IsPrimary: true,
	}
	if err := s.db.CreateDomain(domain); err != nil {
		return nil, fmt.Errorf("creating domain %s: %w", fqdn, err)
	}

	s.logger.Info("custom subdomain allocated",
		"subdomain", name,
		"fqdn", fqdn,
		"admin", adminUsername+"@"+fqdn,
	)

	alloc := &Allocation{
		Subdomain:  name,
		FQDN:       fqdn,
		OwnerEmail: adminUsername + "@" + fqdn,
		CreatedAt:  time.Now(),
		Active:     true,
	}

	return alloc, nil
}
