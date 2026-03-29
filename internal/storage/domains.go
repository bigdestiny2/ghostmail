package storage

import (
	"database/sql"
	"fmt"
	"time"
)

type Domain struct {
	ID             int64
	Name           string
	DKIMSelector   string
	DKIMPrivateKey []byte
	DKIMPublicKey  string
	IsPrimary      bool
	CreatedAt      time.Time
}

// CreateDomain inserts a new domain.
func (db *DB) CreateDomain(d *Domain) error {
	now := time.Now().Unix()
	result, err := db.Exec(`
		INSERT INTO domains (name, dkim_selector, dkim_private_key, dkim_public_key, is_primary, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		d.Name, d.DKIMSelector, d.DKIMPrivateKey, d.DKIMPublicKey, boolToInt(d.IsPrimary), now,
	)
	if err != nil {
		return fmt.Errorf("inserting domain: %w", err)
	}
	d.ID, _ = result.LastInsertId()
	d.CreatedAt = time.Unix(now, 0)
	return nil
}

// GetDomain retrieves a domain by name.
func (db *DB) GetDomain(name string) (*Domain, error) {
	d := &Domain{}
	var isPrimary int
	var createdAt int64

	err := db.QueryRow(`
		SELECT id, name, dkim_selector, dkim_private_key, dkim_public_key, is_primary, created_at
		FROM domains WHERE name = ?`, name,
	).Scan(&d.ID, &d.Name, &d.DKIMSelector, &d.DKIMPrivateKey, &d.DKIMPublicKey, &isPrimary, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying domain: %w", err)
	}
	d.IsPrimary = isPrimary != 0
	d.CreatedAt = time.Unix(createdAt, 0)
	return d, nil
}

// ListDomains returns all configured domains.
func (db *DB) ListDomains() ([]*Domain, error) {
	rows, err := db.Query(`
		SELECT id, name, dkim_selector, dkim_public_key, is_primary, created_at
		FROM domains ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("querying domains: %w", err)
	}
	defer rows.Close()

	var domains []*Domain
	for rows.Next() {
		d := &Domain{}
		var isPrimary int
		var createdAt int64
		if err := rows.Scan(&d.ID, &d.Name, &d.DKIMSelector, &d.DKIMPublicKey, &isPrimary, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning domain: %w", err)
		}
		d.IsPrimary = isPrimary != 0
		d.CreatedAt = time.Unix(createdAt, 0)
		domains = append(domains, d)
	}
	return domains, rows.Err()
}

// DeleteDomain removes a domain by ID.
func (db *DB) DeleteDomain(id int64) error {
	_, err := db.Exec("DELETE FROM domains WHERE id = ?", id)
	return err
}

// IsLocalDomain checks if the given domain is managed by this server.
func (db *DB) IsLocalDomain(name string) (bool, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM domains WHERE name = ?", name).Scan(&count)
	return count > 0, err
}
