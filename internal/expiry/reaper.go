// Package expiry handles automatic deletion of expired messages.
package expiry

import (
	"context"
	"log/slog"
	"time"

	"github.com/ghostmail/ghostmail/internal/config"
	"github.com/ghostmail/ghostmail/internal/storage"
)

// Reaper periodically deletes expired messages and applies mailbox TTL defaults.
type Reaper struct {
	db             *storage.DB
	logger         *slog.Logger
	sweepInterval  time.Duration
	vacuumInterval time.Duration
	trashTTL       time.Duration
	spamTTL        time.Duration
}

// NewReaper creates a new message expiry reaper.
func NewReaper(cfg *config.Config, db *storage.DB, logger *slog.Logger) (*Reaper, error) {
	sweep, err := config.ParseDuration(cfg.Expiry.SweepInterval)
	if err != nil {
		return nil, err
	}
	vacuum, err := config.ParseDuration(cfg.Expiry.VacuumInterval)
	if err != nil {
		return nil, err
	}

	var trashTTL, spamTTL time.Duration
	if cfg.Expiry.TrashTTL != "" {
		trashTTL, err = config.ParseDuration(cfg.Expiry.TrashTTL)
		if err != nil {
			return nil, err
		}
	}
	if cfg.Expiry.SpamTTL != "" {
		spamTTL, err = config.ParseDuration(cfg.Expiry.SpamTTL)
		if err != nil {
			return nil, err
		}
	}

	return &Reaper{
		db:             db,
		logger:         logger,
		sweepInterval:  sweep,
		vacuumInterval: vacuum,
		trashTTL:       trashTTL,
		spamTTL:        spamTTL,
	}, nil
}

// Run starts the reaper background loop.
func (r *Reaper) Run(ctx context.Context) {
	sweepTicker := time.NewTicker(r.sweepInterval)
	vacuumTicker := time.NewTicker(r.vacuumInterval)
	defer sweepTicker.Stop()
	defer vacuumTicker.Stop()

	// Apply mailbox TTL defaults on startup
	r.applyMailboxTTLs()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sweepTicker.C:
			r.sweep()
			r.applyMailboxTTLs()
		case <-vacuumTicker.C:
			r.vacuum()
		}
	}
}

func (r *Reaper) sweep() {
	count, err := r.db.DeleteExpiredMessages(time.Now().Unix())
	if err != nil {
		r.logger.Error("expiry sweep failed", "error", err)
		return
	}
	if count > 0 {
		r.logger.Info("expired messages cleaned", "count", count)
	}
}

func (r *Reaper) vacuum() {
	if err := r.db.Vacuum(); err != nil {
		r.logger.Error("vacuum failed", "error", err)
		return
	}
	r.logger.Debug("database vacuumed")
}

// applyMailboxTTLs sets expiry on messages in Trash/Spam that don't have one yet.
func (r *Reaper) applyMailboxTTLs() {
	if r.trashTTL > 0 {
		r.setTTLForMailbox("Trash", r.trashTTL)
	}
	if r.spamTTL > 0 {
		r.setTTLForMailbox("Spam", r.spamTTL)
	}
}

func (r *Reaper) setTTLForMailbox(mailboxName string, ttl time.Duration) {
	expiresAt := time.Now().Add(ttl).Unix()
	result, err := r.db.Exec(`
		UPDATE messages SET expires_at = ?
		WHERE expires_at IS NULL
		AND mailbox_id IN (SELECT id FROM mailboxes WHERE name = ?)`,
		expiresAt, mailboxName,
	)
	if err != nil {
		r.logger.Error("failed to apply mailbox TTL", "mailbox", mailboxName, "error", err)
		return
	}
	affected, _ := result.RowsAffected()
	if affected > 0 {
		r.logger.Info("applied mailbox TTL", "mailbox", mailboxName, "ttl", ttl, "messages", affected)
	}
}
