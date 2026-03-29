package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"math"
	"net"
	gosmtp "net/smtp"
	"strings"
	"time"

	"github.com/ghostmail/ghostmail/internal/config"
	"github.com/ghostmail/ghostmail/internal/crypto"
	"github.com/ghostmail/ghostmail/internal/dkim"
	"github.com/ghostmail/ghostmail/internal/storage"
)

// Sender handles outbound email delivery from the send queue.
type Sender struct {
	db     *storage.DB
	cfg    *config.Config
	logger *slog.Logger

	retryBaseDelay  time.Duration
	deadLetterAfter time.Duration
	signers         map[string]*dkim.Signer // domain -> signer
	pgpSvc          *crypto.PGPService
}

// NewSender creates a new outbound mail sender.
func NewSender(cfg *config.Config, db *storage.DB, logger *slog.Logger) (*Sender, error) {
	retryDelay, err := config.ParseDuration(cfg.SMTP.Outbound.RetryBaseDelay)
	if err != nil {
		return nil, fmt.Errorf("parsing retry_base_delay: %w", err)
	}
	deadLetter, err := config.ParseDuration(cfg.SMTP.Outbound.DeadLetterAfter)
	if err != nil {
		return nil, fmt.Errorf("parsing dead_letter_after: %w", err)
	}

	sender := &Sender{
		db:              db,
		cfg:             cfg,
		logger:          logger,
		retryBaseDelay:  retryDelay,
		deadLetterAfter: deadLetter,
		signers:         make(map[string]*dkim.Signer),
		pgpSvc:          crypto.NewPGPService(),
	}

	// Load DKIM signing keys from configured domains
	sender.loadDKIMKeys()

	return sender, nil
}

// loadDKIMKeys loads DKIM signing keys for all domains with DKIM configured.
func (s *Sender) loadDKIMKeys() {
	domains, err := s.db.ListDomains()
	if err != nil {
		s.logger.Warn("failed to load domains for DKIM", "error", err)
		return
	}

	for _, d := range domains {
		if d.DKIMSelector == "" || len(d.DKIMPrivateKey) == 0 {
			continue
		}
		signer, err := dkim.NewRSASigner(d.Name, d.DKIMSelector, d.DKIMPrivateKey)
		if err != nil {
			s.logger.Warn("failed to load DKIM key", "domain", d.Name, "error", err)
			continue
		}
		s.signers[d.Name] = signer
		s.logger.Info("DKIM signer loaded", "domain", d.Name, "selector", d.DKIMSelector)
	}
}

// Run starts the send queue processor. It runs until the context is cancelled.
func (s *Sender) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.processQueue()
		}
	}
}

func (s *Sender) processQueue() {
	items, err := s.db.DequeueMessages(s.cfg.SMTP.Outbound.ConcurrentDeliveries)
	if err != nil {
		s.logger.Error("failed to dequeue messages", "error", err)
		return
	}

	for _, item := range items {
		if err := s.db.MarkSending(item.ID); err != nil {
			s.logger.Error("failed to mark sending", "id", item.ID, "error", err)
			continue
		}

		if err := s.deliver(item); err != nil {
			s.handleFailure(item, err)
		} else {
			if err := s.db.MarkSent(item.ID); err != nil {
				s.logger.Error("failed to mark sent", "id", item.ID, "error", err)
			}
			s.logger.Info("message sent", "to", item.ToAddr)
		}
	}
}

func (s *Sender) deliver(item *storage.QueueItem) error {
	// Extract domain from recipient
	parts := strings.SplitN(item.ToAddr, "@", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid recipient: %s", item.ToAddr)
	}

	// Privacy: strip identifying headers before sending
	message := StripHeaders(item.MessageData, s.cfg.Server.Hostname, StripConfig{
		StripReceived:      s.cfg.Privacy.StripReceivedHeaders,
		StripUserAgent:     s.cfg.Privacy.StripUserAgent,
		StripXOrigIP:       s.cfg.Privacy.StripXOriginatingIP,
		NormalizeMessageID: s.cfg.Privacy.NormalizeMessageID,
	})

	// PGP encrypt if recipient has a known public key in the keyring
	recipientAddr := extractAddr(item.ToAddr)
	message = s.tryPGPEncrypt(recipientAddr, message)

	// DKIM sign if we have a signer for the sender's domain
	senderParts := strings.SplitN(item.FromAddr, "@", 2)
	if len(senderParts) == 2 {
		senderDomain := strings.TrimSuffix(strings.TrimPrefix(senderParts[1], "<"), ">")
		if signer, ok := s.signers[senderDomain]; ok {
			signed, err := signer.Sign(message)
			if err != nil {
				s.logger.Warn("DKIM signing failed, sending unsigned", "domain", senderDomain, "error", err)
			} else {
				message = signed
			}
		}
	}

	// Replace message data with processed version for delivery
	item.MessageData = message
	domain := parts[1]

	// Look up MX records
	mxRecords, err := net.LookupMX(domain)
	if err != nil || len(mxRecords) == 0 {
		// Fall back to A/AAAA record
		mxRecords = []*net.MX{{Host: domain, Pref: 0}}
	}

	// Try each MX in order of priority
	var lastErr error
	for _, mx := range mxRecords {
		host := strings.TrimSuffix(mx.Host, ".")
		addr := host + ":25"

		err := s.sendToHost(addr, item)
		if err == nil {
			return nil
		}
		lastErr = err
		s.logger.Warn("MX delivery attempt failed", "host", host, "error", err)
	}

	return fmt.Errorf("all MX hosts failed: %w", lastErr)
}

func (s *Sender) sendToHost(addr string, item *storage.QueueItem) error {
	from := extractAddr(item.FromAddr)

	c, err := gosmtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer c.Close()

	// Try STARTTLS (best-effort in Phase 1; Phase 4 will add strict TLS)
	if ok, _ := c.Extension("STARTTLS"); ok {
		host := strings.Split(addr, ":")[0]
		tlsCfg := &tls.Config{ServerName: host}
		if err := c.StartTLS(tlsCfg); err != nil {
			_ = err // Continue without TLS for now
		}
	}

	if err := c.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := c.Rcpt(extractAddr(item.ToAddr)); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write(item.MessageData); err != nil {
		return fmt.Errorf("writing message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("closing data: %w", err)
	}

	return c.Quit()
}

func (s *Sender) handleFailure(item *storage.QueueItem, deliveryErr error) {
	// Check if we've exceeded the dead letter threshold
	if time.Since(item.CreatedAt) > s.deadLetterAfter {
		s.db.MarkDeadLetter(item.ID, deliveryErr.Error())
		s.logger.Error("message dead-lettered", "to", item.ToAddr, "error", deliveryErr)
		return
	}

	// Check max retries
	if item.Attempts >= s.cfg.SMTP.Outbound.MaxRetries {
		s.db.MarkDeadLetter(item.ID, deliveryErr.Error())
		s.logger.Error("message dead-lettered (max retries)", "to", item.ToAddr, "error", deliveryErr)
		return
	}

	// Exponential backoff
	delay := s.retryBaseDelay * time.Duration(math.Pow(2, float64(item.Attempts)))
	nextRetry := time.Now().Add(delay)

	if err := s.db.MarkFailed(item.ID, deliveryErr.Error(), nextRetry); err != nil {
		s.logger.Error("failed to reschedule", "id", item.ID, "error", err)
	}
	s.logger.Warn("message delivery failed, will retry",
		"to", item.ToAddr, "attempt", item.Attempts+1, "next_retry", nextRetry)
}

// tryPGPEncrypt checks if the recipient has a PGP key in any user's keyring
// and encrypts the message if so. Returns the original message if no key found.
func (s *Sender) tryPGPEncrypt(recipientAddr string, message []byte) []byte {
	// Look up PGP key for recipient across all users' keyrings
	pgpKey, err := s.db.LookupPGPKey(recipientAddr)
	if err != nil || pgpKey == nil {
		return message // No PGP key found, send in cleartext
	}

	encrypted, err := s.pgpSvc.EncryptMIME(message, pgpKey.PublicKey)
	if err != nil {
		s.logger.Warn("PGP encryption failed, sending in cleartext",
			"recipient", recipientAddr, "error", err)
		return message
	}

	s.logger.Info("message PGP-encrypted for recipient", "recipient", recipientAddr)
	return encrypted
}
