package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

type AuditEntry struct {
	ID        int64
	Actor     string
	Action    string
	Target    string
	Timestamp time.Time
	ChainHash string
}

// LogAudit records an admin action. No message content is ever logged.
// Each entry includes a SHA-256 hash chain for tamper detection.
func (db *DB) LogAudit(actor, action, target string) error {
	now := time.Now().UTC()
	nowUnix := now.Unix()
	nowStr := now.Format(time.RFC3339)

	// Get previous chain hash
	var prevHash string
	db.QueryRow(`SELECT COALESCE(chain_hash, '') FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&prevHash)

	// Compute new chain hash: SHA-256(prev_hash|actor|action|target|timestamp)
	data := fmt.Sprintf("%s|%s|%s|%s|%s", prevHash, actor, action, target, nowStr)
	hash := sha256.Sum256([]byte(data))
	chainHash := hex.EncodeToString(hash[:])

	_, err := db.Exec(`
		INSERT INTO audit_log (actor, action, target, timestamp, chain_hash)
		VALUES (?, ?, ?, ?, ?)`,
		actor, action, target, nowUnix, chainHash,
	)
	return err
}

// ListAuditLog returns the most recent audit entries.
func (db *DB) ListAuditLog(limit int) ([]*AuditEntry, error) {
	rows, err := db.Query(`
		SELECT id, actor, action, target, timestamp, COALESCE(chain_hash, '')
		FROM audit_log ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("querying audit log: %w", err)
	}
	defer rows.Close()

	var entries []*AuditEntry
	for rows.Next() {
		e := &AuditEntry{}
		var ts int64
		if err := rows.Scan(&e.ID, &e.Actor, &e.Action, &e.Target, &ts, &e.ChainHash); err != nil {
			return nil, fmt.Errorf("scanning audit entry: %w", err)
		}
		e.Timestamp = time.Unix(ts, 0)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// VerifyAuditChain walks the entire audit log in insertion order and verifies
// that each entry's chain_hash matches the expected SHA-256 hash. Returns
// (true, 0, nil) if the chain is intact, or (false, brokenID, nil) with the ID
// of the first entry whose hash does not match.
func (db *DB) VerifyAuditChain() (bool, int, error) {
	rows, err := db.Query(`
		SELECT id, actor, action, COALESCE(target, ''), timestamp, COALESCE(chain_hash, '')
		FROM audit_log ORDER BY id ASC`)
	if err != nil {
		return false, 0, fmt.Errorf("querying audit log for verification: %w", err)
	}
	defer rows.Close()

	prevHash := ""
	for rows.Next() {
		var id int
		var actor, action, target, chainHash string
		var ts int64
		if err := rows.Scan(&id, &actor, &action, &target, &ts, &chainHash); err != nil {
			return false, 0, fmt.Errorf("scanning audit entry: %w", err)
		}

		// Recompute the expected hash using the stored timestamp
		nowStr := time.Unix(ts, 0).UTC().Format(time.RFC3339)
		data := fmt.Sprintf("%s|%s|%s|%s|%s", prevHash, actor, action, target, nowStr)
		hash := sha256.Sum256([]byte(data))
		expected := hex.EncodeToString(hash[:])

		if chainHash != expected {
			return false, id, nil
		}

		prevHash = chainHash
	}
	if err := rows.Err(); err != nil {
		return false, 0, fmt.Errorf("iterating audit log: %w", err)
	}

	return true, 0, nil
}

// LogSecurityEvent logs a security-related event with a "security." prefix on the action.
func (db *DB) LogSecurityEvent(actor, action, detail string) {
	db.LogAudit(actor, "security."+action, detail)
}
