package storage

import (
	"database/sql"
	"fmt"
	"time"
)

// QueueStatus represents the state of a queued message.
const (
	QueuePending  = 0
	QueueSending  = 1
	QueueSent     = 2
	QueueFailed   = 3
)

type QueueItem struct {
	ID          int64
	FromAddr    string
	ToAddr      string
	MessageData []byte
	Attempts    int
	NextRetryAt time.Time
	LastError   string
	CreatedAt   time.Time
	Status      int
	UserID      *int64
}

// EnqueueMessage adds a message to the outbound send queue.
func (db *DB) EnqueueMessage(from, to string, data []byte) error {
	now := time.Now().Unix()
	_, err := db.Exec(`
		INSERT INTO send_queue (from_addr, to_addr, message_data, attempts, next_retry_at, created_at, status)
		VALUES (?, ?, ?, 0, ?, ?, ?)`,
		from, to, data, now, now, QueuePending,
	)
	return err
}

// EnqueueMessageForUser adds a message to the outbound send queue with user association.
func (db *DB) EnqueueMessageForUser(from, to string, data []byte, userID int64) error {
	now := time.Now().Unix()
	_, err := db.Exec(`
		INSERT INTO send_queue (from_addr, to_addr, message_data, attempts, next_retry_at, created_at, status, user_id)
		VALUES (?, ?, ?, 0, ?, ?, ?, ?)`,
		from, to, data, now, now, QueuePending, userID,
	)
	return err
}

// DequeueMessages returns up to limit messages ready for delivery.
func (db *DB) DequeueMessages(limit int) ([]*QueueItem, error) {
	now := time.Now().Unix()
	rows, err := db.Query(`
		SELECT id, from_addr, to_addr, message_data, attempts, next_retry_at, last_error, created_at, status
		FROM send_queue
		WHERE status = ? AND next_retry_at <= ?
		ORDER BY next_retry_at
		LIMIT ?`,
		QueuePending, now, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("querying send queue: %w", err)
	}
	defer rows.Close()

	var items []*QueueItem
	for rows.Next() {
		item := &QueueItem{}
		var nextRetry, createdAt int64
		var lastError sql.NullString
		if err := rows.Scan(
			&item.ID, &item.FromAddr, &item.ToAddr, &item.MessageData,
			&item.Attempts, &nextRetry, &lastError, &createdAt, &item.Status,
		); err != nil {
			return nil, fmt.Errorf("scanning queue item: %w", err)
		}
		item.NextRetryAt = time.Unix(nextRetry, 0)
		item.CreatedAt = time.Unix(createdAt, 0)
		if lastError.Valid {
			item.LastError = lastError.String
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// MarkSending sets a queue item to "sending" status.
func (db *DB) MarkSending(id int64) error {
	_, err := db.Exec("UPDATE send_queue SET status = ? WHERE id = ?", QueueSending, id)
	return err
}

// MarkSent marks a queue item as successfully sent.
func (db *DB) MarkSent(id int64) error {
	_, err := db.Exec("UPDATE send_queue SET status = ? WHERE id = ?", QueueSent, id)
	return err
}

// MarkFailed records a delivery failure with retry scheduling.
func (db *DB) MarkFailed(id int64, lastError string, nextRetry time.Time) error {
	_, err := db.Exec(`
		UPDATE send_queue SET status = ?, attempts = attempts + 1,
			last_error = ?, next_retry_at = ?
		WHERE id = ?`,
		QueuePending, lastError, nextRetry.Unix(), id,
	)
	return err
}

// MarkDeadLetter marks a queue item as permanently failed.
func (db *DB) MarkDeadLetter(id int64, lastError string) error {
	_, err := db.Exec(`
		UPDATE send_queue SET status = ?, last_error = ?, attempts = attempts + 1
		WHERE id = ?`,
		QueueFailed, lastError, id,
	)
	return err
}

// DeleteQueueItem removes a queue item.
func (db *DB) DeleteQueueItem(id int64) error {
	_, err := db.Exec("DELETE FROM send_queue WHERE id = ?", id)
	return err
}

// QueueSize returns the number of pending messages in the queue.
func (db *DB) QueueSize() (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM send_queue WHERE status = ?", QueuePending).Scan(&count)
	return count, err
}

// CleanSentMessages removes successfully delivered messages older than the given age.
func (db *DB) CleanSentMessages(olderThan time.Time) (int64, error) {
	result, err := db.Exec(
		"DELETE FROM send_queue WHERE status = ? AND created_at < ?",
		QueueSent, olderThan.Unix(),
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
