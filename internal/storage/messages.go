package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type Message struct {
	ID              int64
	MailboxID       int64
	UID             int
	MessageKeyEnc   []byte
	MessageKeyNonce []byte
	HeaderEnc       []byte
	HeaderNonce     []byte
	BodyEnc         []byte
	BodyNonce       []byte
	Size            int
	Flags           string
	InternalDate    time.Time
	ExpiresAt       *time.Time
	EnvelopeEnc     []byte
	EnvelopeNonce   []byte
}

// StoreMessage stores a message in the specified mailbox, auto-assigning the next UID.
func (db *DB) StoreMessage(msg *Message) error {
	uid, err := db.NextUID(msg.MailboxID)
	if err != nil {
		return fmt.Errorf("allocating UID: %w", err)
	}
	msg.UID = uid

	var expiresAt *int64
	if msg.ExpiresAt != nil {
		v := msg.ExpiresAt.Unix()
		expiresAt = &v
	}

	result, err := db.Exec(`
		INSERT INTO messages (mailbox_id, uid, message_key_enc, message_key_nonce,
			header_enc, header_nonce, body_enc, body_nonce,
			size, flags, internal_date, expires_at,
			envelope_enc, envelope_nonce)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		msg.MailboxID, msg.UID, msg.MessageKeyEnc, msg.MessageKeyNonce,
		msg.HeaderEnc, msg.HeaderNonce, msg.BodyEnc, msg.BodyNonce,
		msg.Size, msg.Flags, msg.InternalDate.Unix(), expiresAt,
		msg.EnvelopeEnc, msg.EnvelopeNonce,
	)
	if err != nil {
		return fmt.Errorf("inserting message: %w", err)
	}
	msg.ID, _ = result.LastInsertId()
	return nil
}

// GetMessage retrieves a message by mailbox ID and UID.
func (db *DB) GetMessage(mailboxID int64, uid int) (*Message, error) {
	msg := &Message{}
	var internalDate int64
	var expiresAt sql.NullInt64

	err := db.QueryRow(`
		SELECT id, mailbox_id, uid, message_key_enc, message_key_nonce,
			header_enc, header_nonce, body_enc, body_nonce,
			size, flags, internal_date, expires_at,
			envelope_enc, envelope_nonce
		FROM messages WHERE mailbox_id = ? AND uid = ?`,
		mailboxID, uid,
	).Scan(
		&msg.ID, &msg.MailboxID, &msg.UID, &msg.MessageKeyEnc, &msg.MessageKeyNonce,
		&msg.HeaderEnc, &msg.HeaderNonce, &msg.BodyEnc, &msg.BodyNonce,
		&msg.Size, &msg.Flags, &internalDate, &expiresAt,
		&msg.EnvelopeEnc, &msg.EnvelopeNonce,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying message: %w", err)
	}

	msg.InternalDate = time.Unix(internalDate, 0)
	if expiresAt.Valid {
		t := time.Unix(expiresAt.Int64, 0)
		msg.ExpiresAt = &t
	}
	return msg, nil
}

// ListMessages returns all messages in a mailbox ordered by UID.
func (db *DB) ListMessages(mailboxID int64) ([]*Message, error) {
	rows, err := db.Query(`
		SELECT id, mailbox_id, uid, message_key_enc, message_key_nonce,
			header_enc, header_nonce, body_enc, body_nonce,
			size, flags, internal_date, expires_at,
			envelope_enc, envelope_nonce
		FROM messages WHERE mailbox_id = ? ORDER BY uid`, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("querying messages: %w", err)
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		msg := &Message{}
		var internalDate int64
		var expiresAt sql.NullInt64

		if err := rows.Scan(
			&msg.ID, &msg.MailboxID, &msg.UID, &msg.MessageKeyEnc, &msg.MessageKeyNonce,
			&msg.HeaderEnc, &msg.HeaderNonce, &msg.BodyEnc, &msg.BodyNonce,
			&msg.Size, &msg.Flags, &internalDate, &expiresAt,
			&msg.EnvelopeEnc, &msg.EnvelopeNonce,
		); err != nil {
			return nil, fmt.Errorf("scanning message: %w", err)
		}

		msg.InternalDate = time.Unix(internalDate, 0)
		if expiresAt.Valid {
			t := time.Unix(expiresAt.Int64, 0)
			msg.ExpiresAt = &t
		}
		messages = append(messages, msg)
	}
	return messages, rows.Err()
}

// UpdateFlags sets the flags on a message.
func (db *DB) UpdateFlags(messageID int64, flags string) error {
	_, err := db.Exec("UPDATE messages SET flags = ? WHERE id = ?", flags, messageID)
	return err
}

// DeleteMessage removes a message by ID.
func (db *DB) DeleteMessage(id int64) error {
	_, err := db.Exec("DELETE FROM messages WHERE id = ?", id)
	return err
}

// DeleteExpiredMessages removes all messages past their expiry time. Returns count deleted.
func (db *DB) DeleteExpiredMessages(now int64) (int64, error) {
	result, err := db.Exec(
		"DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ?", now)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ListMessagesPaginated returns messages in a mailbox with pagination, ordered by UID descending (newest first).
func (db *DB) ListMessagesPaginated(mailboxID int64, limit, offset int) ([]*Message, error) {
	rows, err := db.Query(`
		SELECT id, mailbox_id, uid, message_key_enc, message_key_nonce,
			header_enc, header_nonce, body_enc, body_nonce,
			size, flags, internal_date, expires_at,
			envelope_enc, envelope_nonce
		FROM messages WHERE mailbox_id = ? ORDER BY uid DESC LIMIT ? OFFSET ?`,
		mailboxID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("querying messages: %w", err)
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		msg := &Message{}
		var internalDate int64
		var expiresAt sql.NullInt64

		if err := rows.Scan(
			&msg.ID, &msg.MailboxID, &msg.UID, &msg.MessageKeyEnc, &msg.MessageKeyNonce,
			&msg.HeaderEnc, &msg.HeaderNonce, &msg.BodyEnc, &msg.BodyNonce,
			&msg.Size, &msg.Flags, &internalDate, &expiresAt,
			&msg.EnvelopeEnc, &msg.EnvelopeNonce,
		); err != nil {
			return nil, fmt.Errorf("scanning message: %w", err)
		}

		msg.InternalDate = time.Unix(internalDate, 0)
		if expiresAt.Valid {
			t := time.Unix(expiresAt.Int64, 0)
			msg.ExpiresAt = &t
		}
		messages = append(messages, msg)
	}
	return messages, rows.Err()
}

// MailboxUnreadCount returns the count of messages without the \Seen flag.
func (db *DB) MailboxUnreadCount(mailboxID int64) (int, error) {
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM messages
		WHERE mailbox_id = ? AND (flags NOT LIKE '%\Seen%' OR flags = '')`,
		mailboxID).Scan(&count)
	return count, err
}

// MoveMessage moves a message to a different mailbox atomically.
func (db *DB) MoveMessage(messageID, destMailboxID int64) error {
	uid, err := db.NextUID(destMailboxID)
	if err != nil {
		return fmt.Errorf("allocating UID: %w", err)
	}
	_, err = db.Exec("UPDATE messages SET mailbox_id = ?, uid = ? WHERE id = ?",
		destMailboxID, uid, messageID)
	return err
}

// GetMessageByID retrieves a message by its internal ID.
func (db *DB) GetMessageByID(id int64) (*Message, error) {
	msg := &Message{}
	var internalDate int64
	var expiresAt sql.NullInt64

	err := db.QueryRow(`
		SELECT id, mailbox_id, uid, message_key_enc, message_key_nonce,
			header_enc, header_nonce, body_enc, body_nonce,
			size, flags, internal_date, expires_at,
			envelope_enc, envelope_nonce
		FROM messages WHERE id = ?`, id,
	).Scan(
		&msg.ID, &msg.MailboxID, &msg.UID, &msg.MessageKeyEnc, &msg.MessageKeyNonce,
		&msg.HeaderEnc, &msg.HeaderNonce, &msg.BodyEnc, &msg.BodyNonce,
		&msg.Size, &msg.Flags, &internalDate, &expiresAt,
		&msg.EnvelopeEnc, &msg.EnvelopeNonce,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying message: %w", err)
	}

	msg.InternalDate = time.Unix(internalDate, 0)
	if expiresAt.Valid {
		t := time.Unix(expiresAt.Int64, 0)
		msg.ExpiresAt = &t
	}
	return msg, nil
}

// HasFlag checks if a message has a specific flag.
func HasFlag(flags, flag string) bool {
	for _, f := range strings.Fields(flags) {
		if strings.EqualFold(f, flag) {
			return true
		}
	}
	return false
}

// AddFlag adds a flag to a flag string if not already present.
func AddFlag(flags, flag string) string {
	if HasFlag(flags, flag) {
		return flags
	}
	if flags == "" {
		return flag
	}
	return flags + " " + flag
}

// RemoveFlag removes a flag from a flag string.
func RemoveFlag(flags, flag string) string {
	parts := strings.Fields(flags)
	result := make([]string, 0, len(parts))
	for _, f := range parts {
		if !strings.EqualFold(f, flag) {
			result = append(result, f)
		}
	}
	return strings.Join(result, " ")
}
