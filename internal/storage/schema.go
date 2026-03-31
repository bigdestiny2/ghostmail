package storage

import "fmt"

// Schema version tracking and migrations.
const currentSchemaVersion = 6

var migrations = []string{
	// Version 1: Initial schema
	`
	CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS users (
		id                  INTEGER PRIMARY KEY AUTOINCREMENT,
		username            TEXT NOT NULL,
		domain              TEXT NOT NULL,
		password_hash       TEXT NOT NULL DEFAULT '',
		public_key          BLOB,
		wrapped_private_key BLOB,
		key_nonce           BLOB,
		key_params          TEXT NOT NULL DEFAULT '{}',
		pgp_public_key      BLOB,
		pgp_private_key_enc BLOB,
		is_admin            INTEGER NOT NULL DEFAULT 0,
		created_at          INTEGER NOT NULL,
		updated_at          INTEGER NOT NULL,
		quota_bytes         INTEGER NOT NULL DEFAULT 104857600,
		UNIQUE(username, domain)
	);

	CREATE TABLE IF NOT EXISTS domains (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		name            TEXT NOT NULL UNIQUE,
		dkim_selector   TEXT,
		dkim_private_key BLOB,
		dkim_public_key TEXT,
		is_primary      INTEGER NOT NULL DEFAULT 0,
		created_at      INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS mailboxes (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		name         TEXT NOT NULL,
		uid_validity INTEGER NOT NULL,
		uid_next     INTEGER NOT NULL DEFAULT 1,
		subscribed   INTEGER NOT NULL DEFAULT 1,
		special_use  TEXT DEFAULT '',
		UNIQUE(user_id, name)
	);

	CREATE TABLE IF NOT EXISTS messages (
		id                INTEGER PRIMARY KEY AUTOINCREMENT,
		mailbox_id        INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
		uid               INTEGER NOT NULL,
		message_key_enc   BLOB,
		message_key_nonce BLOB,
		header_enc        BLOB,
		header_nonce      BLOB,
		body_enc          BLOB NOT NULL,
		body_nonce        BLOB,
		size              INTEGER NOT NULL,
		flags             TEXT NOT NULL DEFAULT '',
		internal_date     INTEGER NOT NULL,
		expires_at        INTEGER,
		envelope_enc      BLOB,
		envelope_nonce    BLOB,
		UNIQUE(mailbox_id, uid)
	);
	CREATE INDEX IF NOT EXISTS idx_messages_mailbox ON messages(mailbox_id);
	CREATE INDEX IF NOT EXISTS idx_messages_expires ON messages(expires_at) WHERE expires_at IS NOT NULL;

	CREATE TABLE IF NOT EXISTS search_tokens (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
		token_hash BLOB NOT NULL,
		field      INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_search_tokens ON search_tokens(token_hash, field);

	CREATE TABLE IF NOT EXISTS aliases (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		address       TEXT NOT NULL UNIQUE,
		domain        TEXT NOT NULL,
		description   TEXT DEFAULT '',
		is_active     INTEGER NOT NULL DEFAULT 1,
		expires_at    INTEGER,
		message_count INTEGER NOT NULL DEFAULT 0,
		max_messages  INTEGER,
		created_at    INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS send_queue (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		from_addr     TEXT NOT NULL,
		to_addr       TEXT NOT NULL,
		message_data  BLOB NOT NULL,
		attempts      INTEGER NOT NULL DEFAULT 0,
		next_retry_at INTEGER NOT NULL,
		last_error    TEXT,
		created_at    INTEGER NOT NULL,
		status        INTEGER NOT NULL DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_send_queue_retry ON send_queue(status, next_retry_at);

	CREATE TABLE IF NOT EXISTS pgp_keyring (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		email       TEXT NOT NULL,
		public_key  BLOB NOT NULL,
		fingerprint TEXT NOT NULL,
		trust_level INTEGER NOT NULL DEFAULT 0,
		created_at  INTEGER NOT NULL,
		UNIQUE(user_id, email)
	);

	CREATE TABLE IF NOT EXISTS audit_log (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		actor     TEXT NOT NULL,
		action    TEXT NOT NULL,
		target    TEXT,
		timestamp INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_audit_log_time ON audit_log(timestamp);
	`,

	// Version 2: Add search_key to users for server-side blind indexing
	`
	ALTER TABLE users ADD COLUMN search_key BLOB;
	`,

	// Version 3: Vault password (split auth from encryption) + payments
	`
	ALTER TABLE users ADD COLUMN vault_hash TEXT NOT NULL DEFAULT '';
	ALTER TABLE users ADD COLUMN vault_key_params TEXT NOT NULL DEFAULT '{}';
	ALTER TABLE users ADD COLUMN vault_key_nonce BLOB;
	ALTER TABLE users ADD COLUMN vault_wrapped_private_key BLOB;

	CREATE TABLE IF NOT EXISTS vault_sessions (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token       TEXT NOT NULL UNIQUE,
		created_at  INTEGER NOT NULL,
		expires_at  INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_vault_sessions_token ON vault_sessions(token);
	CREATE INDEX IF NOT EXISTS idx_vault_sessions_expires ON vault_sessions(expires_at);

	CREATE TABLE IF NOT EXISTS payments (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		tx_hash         TEXT NOT NULL,
		wallet_address  TEXT NOT NULL,
		amount_usd      REAL NOT NULL,
		crypto_currency TEXT NOT NULL DEFAULT 'ETH',
		crypto_amount   TEXT NOT NULL DEFAULT '',
		status          INTEGER NOT NULL DEFAULT 0,
		user_id         INTEGER REFERENCES users(id),
		created_at      INTEGER NOT NULL,
		confirmed_at    INTEGER
	);
	CREATE INDEX IF NOT EXISTS idx_payments_tx ON payments(tx_hash);
	CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status);
	`,

	// Version 4: Add UNIQUE constraint on payments.tx_hash to prevent race condition double-spend
	`
	DROP INDEX IF EXISTS idx_payments_tx;
	CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_tx_unique ON payments(tx_hash);
	`,

	// Version 5: Add user_id to send_queue for user-scoped queue operations + missing indexes
	`
	ALTER TABLE send_queue ADD COLUMN user_id INTEGER REFERENCES users(id);
	CREATE INDEX IF NOT EXISTS idx_send_queue_user ON send_queue(user_id);
	CREATE INDEX IF NOT EXISTS idx_aliases_user ON aliases(user_id);
	CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor);
	CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
	`,

	// Version 6: Add hash chain column to audit_log for tamper detection
	`
	ALTER TABLE audit_log ADD COLUMN chain_hash TEXT DEFAULT '';
	`,
}

func (db *DB) migrate() error {
	// Ensure schema_version table exists
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`)
	if err != nil {
		return fmt.Errorf("creating schema_version table: %w", err)
	}

	var version int
	err = db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&version)
	if err != nil {
		return fmt.Errorf("reading schema version: %w", err)
	}

	for i := version; i < len(migrations); i++ {
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("beginning migration %d: %w", i+1, err)
		}

		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("running migration %d: %w", i+1, err)
		}

		if _, err := tx.Exec("DELETE FROM schema_version"); err != nil {
			tx.Rollback()
			return fmt.Errorf("clearing schema version: %w", err)
		}
		if _, err := tx.Exec("INSERT INTO schema_version (version) VALUES (?)", i+1); err != nil {
			tx.Rollback()
			return fmt.Errorf("updating schema version: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing migration %d: %w", i+1, err)
		}
	}

	return nil
}
