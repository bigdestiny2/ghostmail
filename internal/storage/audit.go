package storage

import (
	"fmt"
	"time"
)

type AuditEntry struct {
	ID        int64
	Actor     string
	Action    string
	Target    string
	Timestamp time.Time
}

// LogAudit records an admin action. No message content is ever logged.
func (db *DB) LogAudit(actor, action, target string) error {
	_, err := db.Exec(`
		INSERT INTO audit_log (actor, action, target, timestamp)
		VALUES (?, ?, ?, ?)`,
		actor, action, target, time.Now().Unix(),
	)
	return err
}

// ListAuditLog returns the most recent audit entries.
func (db *DB) ListAuditLog(limit int) ([]*AuditEntry, error) {
	rows, err := db.Query(`
		SELECT id, actor, action, target, timestamp
		FROM audit_log ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("querying audit log: %w", err)
	}
	defer rows.Close()

	var entries []*AuditEntry
	for rows.Next() {
		e := &AuditEntry{}
		var ts int64
		if err := rows.Scan(&e.ID, &e.Actor, &e.Action, &e.Target, &ts); err != nil {
			return nil, fmt.Errorf("scanning audit entry: %w", err)
		}
		e.Timestamp = time.Unix(ts, 0)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
