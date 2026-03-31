package storage

import (
	"database/sql"
	"fmt"
	"time"
)

type Alias struct {
	ID           int64
	UserID       int64
	Address      string
	Domain       string
	Description  string
	IsActive     bool
	ExpiresAt    *time.Time
	MessageCount int
	MaxMessages  *int
	CreatedAt    time.Time
}

// CreateAlias inserts a new alias.
func (db *DB) CreateAlias(a *Alias) error {
	now := time.Now().Unix()
	var expiresAt *int64
	if a.ExpiresAt != nil {
		v := a.ExpiresAt.Unix()
		expiresAt = &v
	}

	result, err := db.Exec(`
		INSERT INTO aliases (user_id, address, domain, description, is_active,
			expires_at, message_count, max_messages, created_at)
		VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		a.UserID, a.Address, a.Domain, a.Description, boolToInt(a.IsActive),
		expiresAt, a.MaxMessages, now,
	)
	if err != nil {
		return fmt.Errorf("inserting alias: %w", err)
	}
	a.ID, _ = result.LastInsertId()
	a.CreatedAt = time.Unix(now, 0)
	return nil
}

// ResolveAlias finds the user who owns an alias address.
func (db *DB) ResolveAlias(address string) (*Alias, error) {
	a := &Alias{}
	var isActive int
	var expiresAt sql.NullInt64
	var maxMessages sql.NullInt64
	var createdAt int64

	err := db.QueryRow(`
		SELECT id, user_id, address, domain, description, is_active,
			expires_at, message_count, max_messages, created_at
		FROM aliases WHERE address = ?`, address,
	).Scan(
		&a.ID, &a.UserID, &a.Address, &a.Domain, &a.Description, &isActive,
		&expiresAt, &a.MessageCount, &maxMessages, &createdAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("resolving alias: %w", err)
	}

	a.IsActive = isActive != 0
	a.CreatedAt = time.Unix(createdAt, 0)
	if expiresAt.Valid {
		t := time.Unix(expiresAt.Int64, 0)
		a.ExpiresAt = &t
	}
	if maxMessages.Valid {
		v := int(maxMessages.Int64)
		a.MaxMessages = &v
	}
	return a, nil
}

// IncrementAliasCount bumps the message counter for an alias.
func (db *DB) IncrementAliasCount(id int64) error {
	_, err := db.Exec("UPDATE aliases SET message_count = message_count + 1 WHERE id = ?", id)
	return err
}

// ListAliases returns all aliases for a user.
func (db *DB) ListAliases(userID int64) ([]*Alias, error) {
	rows, err := db.Query(`
		SELECT id, user_id, address, domain, description, is_active,
			expires_at, message_count, max_messages, created_at
		FROM aliases WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("querying aliases: %w", err)
	}
	defer rows.Close()

	var aliases []*Alias
	for rows.Next() {
		a := &Alias{}
		var isActive int
		var expiresAt sql.NullInt64
		var maxMessages sql.NullInt64
		var createdAt int64

		if err := rows.Scan(
			&a.ID, &a.UserID, &a.Address, &a.Domain, &a.Description, &isActive,
			&expiresAt, &a.MessageCount, &maxMessages, &createdAt,
		); err != nil {
			return nil, fmt.Errorf("scanning alias: %w", err)
		}

		a.IsActive = isActive != 0
		a.CreatedAt = time.Unix(createdAt, 0)
		if expiresAt.Valid {
			t := time.Unix(expiresAt.Int64, 0)
			a.ExpiresAt = &t
		}
		if maxMessages.Valid {
			v := int(maxMessages.Int64)
			a.MaxMessages = &v
		}
		aliases = append(aliases, a)
	}
	return aliases, rows.Err()
}

// DeleteAlias removes an alias by ID.
func (db *DB) DeleteAlias(id int64) error {
	_, err := db.Exec("DELETE FROM aliases WHERE id = ?", id)
	return err
}

// DeactivateAlias marks an alias as inactive.
func (db *DB) DeactivateAlias(id int64) error {
	_, err := db.Exec("UPDATE aliases SET is_active = 0 WHERE id = ?", id)
	return err
}

// DeleteAliasForUser deletes an alias only if it belongs to the user.
func (db *DB) DeleteAliasForUser(aliasID, userID int64) error {
	result, err := db.Exec(`DELETE FROM aliases WHERE id = ? AND user_id = ?`, aliasID, userID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("alias not found or access denied")
	}
	return nil
}
