package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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

// encryptDKIMKey encrypts a DKIM private key using AES-256-GCM with the
// server key. The nonce is prepended to the ciphertext for self-contained
// storage.
func encryptDKIMKey(key []byte, serverKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(serverKey)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, key, nil)
	// Prepend nonce so the blob is self-contained: [nonce][ciphertext+tag]
	out := make([]byte, len(nonce)+len(ciphertext))
	copy(out[:len(nonce)], nonce)
	copy(out[len(nonce):], ciphertext)
	return out, nil
}

// decryptDKIMKey decrypts a DKIM private key that was encrypted with
// encryptDKIMKey. The first 12 bytes are the GCM nonce.
func decryptDKIMKey(encrypted []byte, serverKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(serverKey)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, fmt.Errorf("encrypted DKIM key too short")
	}
	nonce := encrypted[:nonceSize]
	ciphertext := encrypted[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting DKIM key: %w", err)
	}
	return plaintext, nil
}

// CreateDomain inserts a new domain. If a DKIM server key is configured,
// the private key is encrypted at rest using AES-256-GCM.
func (db *DB) CreateDomain(d *Domain) error {
	now := time.Now().Unix()

	privKey := d.DKIMPrivateKey
	if len(db.dkimServerKey) > 0 && len(privKey) > 0 {
		encrypted, err := encryptDKIMKey(privKey, db.dkimServerKey)
		if err != nil {
			return fmt.Errorf("encrypting DKIM private key: %w", err)
		}
		privKey = encrypted
	}

	result, err := db.Exec(`
		INSERT INTO domains (name, dkim_selector, dkim_private_key, dkim_public_key, is_primary, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		d.Name, d.DKIMSelector, privKey, d.DKIMPublicKey, boolToInt(d.IsPrimary), now,
	)
	if err != nil {
		return fmt.Errorf("inserting domain: %w", err)
	}
	d.ID, _ = result.LastInsertId()
	d.CreatedAt = time.Unix(now, 0)
	return nil
}

// GetDomain retrieves a domain by name. If a DKIM server key is configured,
// the private key is transparently decrypted. Plaintext keys (pre-encryption
// migration) are returned as-is.
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

	// Decrypt the DKIM private key if a server key is configured.
	// Auto-detect: attempt decryption; if it fails the key is likely
	// still stored as plaintext (backwards compatible).
	if len(db.dkimServerKey) > 0 && len(d.DKIMPrivateKey) > 0 {
		decrypted, err := decryptDKIMKey(d.DKIMPrivateKey, db.dkimServerKey)
		if err == nil {
			d.DKIMPrivateKey = decrypted
		}
		// If decryption fails, assume plaintext (pre-migration key)
	}

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
