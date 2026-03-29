package storage

import (
	"database/sql"
	"fmt"
	"time"
)

// PGPKey represents a PGP public key for an external contact.
type PGPKey struct {
	ID          int64
	UserID      int64
	Email       string
	PublicKey   []byte
	Fingerprint string
	TrustLevel  int
	CreatedAt   time.Time
}

// StorePGPKey adds or updates a PGP key for an external contact.
func (db *DB) StorePGPKey(userID int64, email string, publicKey []byte, fingerprint string) error {
	now := time.Now().Unix()

	// Upsert: update if exists, insert if not
	result, err := db.Exec(`
		UPDATE pgp_keyring SET public_key = ?, fingerprint = ?, created_at = ?
		WHERE user_id = ? AND email = ?`,
		publicKey, fingerprint, now, userID, email,
	)
	if err != nil {
		return fmt.Errorf("updating PGP key: %w", err)
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		_, err = db.Exec(`
			INSERT INTO pgp_keyring (user_id, email, public_key, fingerprint, trust_level, created_at)
			VALUES (?, ?, ?, ?, 0, ?)`,
			userID, email, publicKey, fingerprint, now,
		)
		if err != nil {
			return fmt.Errorf("inserting PGP key: %w", err)
		}
	}

	return nil
}

// GetPGPKey retrieves a PGP key for a specific user + email.
func (db *DB) GetPGPKey(userID int64, email string) (*PGPKey, error) {
	k := &PGPKey{}
	var createdAt int64
	err := db.QueryRow(`
		SELECT id, user_id, email, public_key, fingerprint, trust_level, created_at
		FROM pgp_keyring WHERE user_id = ? AND email = ?`,
		userID, email,
	).Scan(&k.ID, &k.UserID, &k.Email, &k.PublicKey, &k.Fingerprint, &k.TrustLevel, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	k.CreatedAt = time.Unix(createdAt, 0)
	return k, nil
}

// LookupPGPKey searches all users' keyrings for a key matching the given email.
// Returns the first match found.
func (db *DB) LookupPGPKey(email string) (*PGPKey, error) {
	k := &PGPKey{}
	var createdAt int64
	err := db.QueryRow(`
		SELECT id, user_id, email, public_key, fingerprint, trust_level, created_at
		FROM pgp_keyring WHERE email = ? LIMIT 1`, email,
	).Scan(&k.ID, &k.UserID, &k.Email, &k.PublicKey, &k.Fingerprint, &k.TrustLevel, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	k.CreatedAt = time.Unix(createdAt, 0)
	return k, nil
}

// ListPGPKeys returns all PGP keys for a user.
func (db *DB) ListPGPKeys(userID int64) ([]*PGPKey, error) {
	rows, err := db.Query(`
		SELECT id, user_id, email, public_key, fingerprint, trust_level, created_at
		FROM pgp_keyring WHERE user_id = ? ORDER BY email`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*PGPKey
	for rows.Next() {
		k := &PGPKey{}
		var createdAt int64
		if err := rows.Scan(&k.ID, &k.UserID, &k.Email, &k.PublicKey, &k.Fingerprint, &k.TrustLevel, &createdAt); err != nil {
			return nil, err
		}
		k.CreatedAt = time.Unix(createdAt, 0)
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// DeletePGPKey removes a PGP key by ID.
func (db *DB) DeletePGPKey(id int64) error {
	_, err := db.Exec("DELETE FROM pgp_keyring WHERE id = ?", id)
	return err
}
