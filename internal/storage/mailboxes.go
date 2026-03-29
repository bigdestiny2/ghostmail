package storage

import (
	"database/sql"
	"fmt"
)

type Mailbox struct {
	ID          int64
	UserID      int64
	Name        string
	UIDValidity int
	UIDNext     int
	Subscribed  bool
	SpecialUse  string
}

// GetMailbox retrieves a mailbox by user ID and name.
func (db *DB) GetMailbox(userID int64, name string) (*Mailbox, error) {
	mb := &Mailbox{}
	var subscribed int
	err := db.QueryRow(`
		SELECT id, user_id, name, uid_validity, uid_next, subscribed, special_use
		FROM mailboxes WHERE user_id = ? AND name = ?`,
		userID, name,
	).Scan(&mb.ID, &mb.UserID, &mb.Name, &mb.UIDValidity, &mb.UIDNext, &subscribed, &mb.SpecialUse)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying mailbox: %w", err)
	}
	mb.Subscribed = subscribed != 0
	return mb, nil
}

// ListMailboxes returns all mailboxes for a user.
func (db *DB) ListMailboxes(userID int64) ([]*Mailbox, error) {
	rows, err := db.Query(`
		SELECT id, user_id, name, uid_validity, uid_next, subscribed, special_use
		FROM mailboxes WHERE user_id = ? ORDER BY name`, userID)
	if err != nil {
		return nil, fmt.Errorf("querying mailboxes: %w", err)
	}
	defer rows.Close()

	var mailboxes []*Mailbox
	for rows.Next() {
		mb := &Mailbox{}
		var subscribed int
		if err := rows.Scan(&mb.ID, &mb.UserID, &mb.Name, &mb.UIDValidity, &mb.UIDNext, &subscribed, &mb.SpecialUse); err != nil {
			return nil, fmt.Errorf("scanning mailbox: %w", err)
		}
		mb.Subscribed = subscribed != 0
		mailboxes = append(mailboxes, mb)
	}
	return mailboxes, rows.Err()
}

// CreateMailbox creates a new mailbox for a user.
func (db *DB) CreateMailbox(mb *Mailbox) error {
	result, err := db.Exec(`
		INSERT INTO mailboxes (user_id, name, uid_validity, uid_next, subscribed, special_use)
		VALUES (?, ?, ?, ?, ?, ?)`,
		mb.UserID, mb.Name, mb.UIDValidity, mb.UIDNext, boolToInt(mb.Subscribed), mb.SpecialUse,
	)
	if err != nil {
		return fmt.Errorf("inserting mailbox: %w", err)
	}
	mb.ID, _ = result.LastInsertId()
	return nil
}

// DeleteMailbox removes a mailbox and all its messages (cascading).
func (db *DB) DeleteMailbox(id int64) error {
	_, err := db.Exec("DELETE FROM mailboxes WHERE id = ?", id)
	return err
}

// NextUID atomically allocates the next UID for a mailbox and returns it.
func (db *DB) NextUID(mailboxID int64) (int, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var uid int
	err = tx.QueryRow("SELECT uid_next FROM mailboxes WHERE id = ?", mailboxID).Scan(&uid)
	if err != nil {
		return 0, fmt.Errorf("reading uid_next: %w", err)
	}

	_, err = tx.Exec("UPDATE mailboxes SET uid_next = uid_next + 1 WHERE id = ?", mailboxID)
	if err != nil {
		return 0, fmt.Errorf("incrementing uid_next: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return uid, nil
}

// MailboxMessageCount returns the number of messages in a mailbox.
func (db *DB) MailboxMessageCount(mailboxID int64) (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM messages WHERE mailbox_id = ?", mailboxID).Scan(&count)
	return count, err
}
