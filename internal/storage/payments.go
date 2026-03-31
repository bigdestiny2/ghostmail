package storage

import (
	"database/sql"
	"fmt"
	"time"
)

// Payment status constants.
const (
	PaymentPending   = 0
	PaymentConfirmed = 1
	PaymentFailed    = 2
)

// Payment represents a crypto payment record.
type Payment struct {
	ID              int64
	TxHash          string
	WalletAddress   string
	AmountUSD       float64
	CryptoCurrency  string
	CryptoAmount    string
	Status          int
	UserID          *int64
	CreatedAt       time.Time
	ConfirmedAt     *time.Time
}

// CreatePayment inserts a new payment record.
func (db *DB) CreatePayment(p *Payment) error {
	result, err := db.Exec(`
		INSERT INTO payments (tx_hash, wallet_address, amount_usd, crypto_currency,
			crypto_amount, status, user_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.TxHash, p.WalletAddress, p.AmountUSD, p.CryptoCurrency,
		p.CryptoAmount, p.Status, p.UserID, time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("inserting payment: %w", err)
	}
	p.ID, _ = result.LastInsertId()
	return nil
}

// GetPaymentByTx retrieves a payment by transaction hash.
func (db *DB) GetPaymentByTx(txHash string) (*Payment, error) {
	p := &Payment{}
	var createdAt int64
	var confirmedAt sql.NullInt64
	var userID sql.NullInt64

	err := db.QueryRow(`
		SELECT id, tx_hash, wallet_address, amount_usd, crypto_currency,
			crypto_amount, status, user_id, created_at, confirmed_at
		FROM payments WHERE tx_hash = ?`, txHash,
	).Scan(
		&p.ID, &p.TxHash, &p.WalletAddress, &p.AmountUSD, &p.CryptoCurrency,
		&p.CryptoAmount, &p.Status, &userID, &createdAt, &confirmedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying payment: %w", err)
	}

	p.CreatedAt = time.Unix(createdAt, 0)
	if confirmedAt.Valid {
		t := time.Unix(confirmedAt.Int64, 0)
		p.ConfirmedAt = &t
	}
	if userID.Valid {
		p.UserID = &userID.Int64
	}
	return p, nil
}

// UpdatePaymentStatus updates a payment's status and optional confirmation time.
func (db *DB) UpdatePaymentStatus(id int64, status int, confirmedAt *time.Time) error {
	var confirmUnix *int64
	if confirmedAt != nil {
		v := confirmedAt.Unix()
		confirmUnix = &v
	}
	_, err := db.Exec(`UPDATE payments SET status = ?, confirmed_at = ? WHERE id = ?`,
		status, confirmUnix, id)
	return err
}

// ListPendingPayments returns all payments with pending status.
func (db *DB) ListPendingPayments() ([]*Payment, error) {
	rows, err := db.Query(`SELECT id, tx_hash, wallet_address, amount_usd, crypto_currency,
		crypto_amount, status, user_id, created_at FROM payments WHERE status = ?`, PaymentPending)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var payments []*Payment
	for rows.Next() {
		p := &Payment{}
		var createdAt int64
		var userID sql.NullInt64
		if err := rows.Scan(&p.ID, &p.TxHash, &p.WalletAddress, &p.AmountUSD,
			&p.CryptoCurrency, &p.CryptoAmount, &p.Status, &userID, &createdAt); err != nil {
			return nil, err
		}
		p.CreatedAt = time.Unix(createdAt, 0)
		if userID.Valid {
			p.UserID = &userID.Int64
		}
		payments = append(payments, p)
	}
	return payments, rows.Err()
}
