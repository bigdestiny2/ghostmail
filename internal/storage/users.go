package storage

import (
	"database/sql"
	"fmt"
	"time"
)

type User struct {
	ID                int64
	Username          string
	Domain            string
	PasswordHash      string
	PublicKey         []byte
	WrappedPrivateKey []byte
	KeyNonce          []byte
	KeyParams         string
	PGPPublicKey      []byte
	PGPPrivateKeyEnc  []byte
	SearchKey         []byte // HMAC key for blind search index (server-held)
	IsAdmin           bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
	QuotaBytes        int64

	// Vault fields (split auth from encryption)
	VaultHash            string // Argon2id-derived vault auth hash
	VaultKeyParams       string // JSON Argon2id params for vault password
	VaultKeyNonce        []byte // Nonce for vault-wrapped private key
	VaultWrappedPrivKey  []byte // Private key encrypted with vault encryption sub-key
}

// CreateUser inserts a new user with default mailboxes.
func (db *DB) CreateUser(u *User) error {
	now := time.Now().Unix()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.Exec(`
		INSERT INTO users (username, domain, password_hash, public_key, wrapped_private_key,
			key_nonce, key_params, search_key, is_admin, created_at, updated_at, quota_bytes,
			vault_hash, vault_key_params, vault_key_nonce, vault_wrapped_private_key)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.Username, u.Domain, u.PasswordHash, u.PublicKey, u.WrappedPrivateKey,
		u.KeyNonce, u.KeyParams, u.SearchKey, boolToInt(u.IsAdmin), now, now, u.QuotaBytes,
		u.VaultHash, u.VaultKeyParams, u.VaultKeyNonce, u.VaultWrappedPrivKey,
	)
	if err != nil {
		return fmt.Errorf("inserting user: %w", err)
	}

	userID, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("getting user ID: %w", err)
	}
	u.ID = userID

	// Create default mailboxes
	defaultMailboxes := []struct {
		name       string
		specialUse string
	}{
		{"INBOX", ""},
		{"Sent", "\\Sent"},
		{"Drafts", "\\Drafts"},
		{"Trash", "\\Trash"},
		{"Spam", "\\Junk"},
	}

	uidValidity := int(now & 0x7FFFFFFF)
	for _, mb := range defaultMailboxes {
		_, err := tx.Exec(`
			INSERT INTO mailboxes (user_id, name, uid_validity, uid_next, subscribed, special_use)
			VALUES (?, ?, ?, 1, 1, ?)`,
			userID, mb.name, uidValidity, mb.specialUse,
		)
		if err != nil {
			return fmt.Errorf("creating mailbox %s: %w", mb.name, err)
		}
	}

	return tx.Commit()
}

// GetUser retrieves a user by username and domain.
func (db *DB) GetUser(username, domain string) (*User, error) {
	u := &User{}
	var isAdmin int
	var createdAt, updatedAt int64

	err := db.QueryRow(`
		SELECT id, username, domain, password_hash, public_key, wrapped_private_key,
			key_nonce, key_params, pgp_public_key, pgp_private_key_enc, search_key,
			is_admin, created_at, updated_at, quota_bytes,
			vault_hash, vault_key_params, vault_key_nonce, vault_wrapped_private_key
		FROM users WHERE username = ? AND domain = ?`,
		username, domain,
	).Scan(
		&u.ID, &u.Username, &u.Domain, &u.PasswordHash, &u.PublicKey, &u.WrappedPrivateKey,
		&u.KeyNonce, &u.KeyParams, &u.PGPPublicKey, &u.PGPPrivateKeyEnc, &u.SearchKey,
		&isAdmin, &createdAt, &updatedAt, &u.QuotaBytes,
		&u.VaultHash, &u.VaultKeyParams, &u.VaultKeyNonce, &u.VaultWrappedPrivKey,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying user: %w", err)
	}

	u.IsAdmin = isAdmin != 0
	u.CreatedAt = time.Unix(createdAt, 0)
	u.UpdatedAt = time.Unix(updatedAt, 0)
	return u, nil
}

// GetUserAuth returns only auth-relevant fields (no private keys, no vault keys).
func (db *DB) GetUserAuth(username, domain string) (*User, error) {
	u := &User{}
	var isAdmin int
	var createdAt, updatedAt int64

	err := db.QueryRow(`
		SELECT id, username, domain, password_hash, key_params, is_admin,
			created_at, updated_at, quota_bytes, public_key
		FROM users WHERE username = ? AND domain = ?`,
		username, domain,
	).Scan(
		&u.ID, &u.Username, &u.Domain, &u.PasswordHash, &u.KeyParams, &isAdmin,
		&createdAt, &updatedAt, &u.QuotaBytes, &u.PublicKey,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying user auth: %w", err)
	}

	u.IsAdmin = isAdmin != 0
	u.CreatedAt = time.Unix(createdAt, 0)
	u.UpdatedAt = time.Unix(updatedAt, 0)
	return u, nil
}

// GetUserByID retrieves a user by ID.
func (db *DB) GetUserByID(id int64) (*User, error) {
	u := &User{}
	var isAdmin int
	var createdAt, updatedAt int64

	err := db.QueryRow(`
		SELECT id, username, domain, password_hash, public_key, wrapped_private_key,
			key_nonce, key_params, pgp_public_key, pgp_private_key_enc, search_key,
			is_admin, created_at, updated_at, quota_bytes,
			vault_hash, vault_key_params, vault_key_nonce, vault_wrapped_private_key
		FROM users WHERE id = ?`, id,
	).Scan(
		&u.ID, &u.Username, &u.Domain, &u.PasswordHash, &u.PublicKey, &u.WrappedPrivateKey,
		&u.KeyNonce, &u.KeyParams, &u.PGPPublicKey, &u.PGPPrivateKeyEnc, &u.SearchKey,
		&isAdmin, &createdAt, &updatedAt, &u.QuotaBytes,
		&u.VaultHash, &u.VaultKeyParams, &u.VaultKeyNonce, &u.VaultWrappedPrivKey,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying user: %w", err)
	}

	u.IsAdmin = isAdmin != 0
	u.CreatedAt = time.Unix(createdAt, 0)
	u.UpdatedAt = time.Unix(updatedAt, 0)
	return u, nil
}

// ListUsers returns all users.
func (db *DB) ListUsers() ([]*User, error) {
	rows, err := db.Query(`
		SELECT id, username, domain, is_admin, created_at, updated_at, quota_bytes
		FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("querying users: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		u := &User{}
		var isAdmin int
		var createdAt, updatedAt int64
		if err := rows.Scan(&u.ID, &u.Username, &u.Domain, &isAdmin, &createdAt, &updatedAt, &u.QuotaBytes); err != nil {
			return nil, fmt.Errorf("scanning user: %w", err)
		}
		u.IsAdmin = isAdmin != 0
		u.CreatedAt = time.Unix(createdAt, 0)
		u.UpdatedAt = time.Unix(updatedAt, 0)
		users = append(users, u)
	}
	return users, rows.Err()
}

// DeleteUser removes a user and all associated data (cascading).
func (db *DB) DeleteUser(id int64) error {
	_, err := db.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}

// UserCount returns the total number of users.
func (db *DB) UserCount() (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

// UserUsageBytes returns total bytes used across all mailboxes for a user.
func (db *DB) UserUsageBytes(userID int64) (int64, error) {
	var total int64
	err := db.QueryRow(`
		SELECT COALESCE(SUM(m.size), 0)
		FROM messages m
		JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE mb.user_id = ?`, userID).Scan(&total)
	return total, err
}

// IsVaultUser returns true if the user has vault-based encryption enabled.
func (u *User) IsVaultUser() bool {
	return u.VaultHash != "" && u.VaultHash != "{}"
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
