package smtp

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/ghostmail/ghostmail/internal/config"
	"github.com/ghostmail/ghostmail/internal/crypto"
	"github.com/ghostmail/ghostmail/internal/dkim"
	"github.com/ghostmail/ghostmail/internal/storage"
)

// Backend implements smtp.Backend.
type Backend struct {
	db          *storage.DB
	cfg         *config.Config
	logger      *slog.Logger
	cryptoSvc   *crypto.Service
	requireAuth bool
}

func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &Session{
		db:          b.db,
		cfg:         b.cfg,
		logger:      b.logger,
		cryptoSvc:   b.cryptoSvc,
		requireAuth: b.requireAuth,
	}, nil
}

// Session handles a single SMTP connection.
type Session struct {
	db          *storage.DB
	cfg         *config.Config
	logger      *slog.Logger
	cryptoSvc   *crypto.Service
	requireAuth bool

	// Set during the session
	authUser *storage.User
	from     string
	to       []string
}

// AuthMechanisms returns supported SASL mechanisms.
func (s *Session) AuthMechanisms() []string {
	return []string{sasl.Plain}
}

// Auth handles SASL authentication.
func (s *Session) Auth(mech string) (sasl.Server, error) {
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, password string) error {
			return s.authenticate(username, password)
		}), nil
	default:
		return nil, fmt.Errorf("unsupported mechanism")
	}
}

func (s *Session) authenticate(username, password string) error {
	// Split username into local@domain
	parts := strings.SplitN(username, "@", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid username format, use user@domain")
	}

	user, err := s.db.GetUser(parts[0], parts[1])
	if err != nil {
		return fmt.Errorf("authentication error")
	}
	if user == nil {
		return fmt.Errorf("invalid credentials")
	}

	// Verify password using Argon2id-derived auth hash
	// Works for both vault users and legacy users — the auth password is
	// always verified via the password_hash field.
	authHash, err := hex.DecodeString(user.PasswordHash)
	if err != nil || len(authHash) == 0 {
		return fmt.Errorf("invalid credentials")
	}
	params, err := crypto.UnmarshalKeyParams(user.KeyParams)
	if err != nil {
		return fmt.Errorf("invalid credentials")
	}
	if !crypto.VerifyPassword([]byte(password), params, authHash) {
		return fmt.Errorf("invalid credentials")
	}

	s.authUser = user
	s.logger.Info("SMTP auth success", "user", username)
	return nil
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	if s.requireAuth && s.authUser == nil {
		return fmt.Errorf("authentication required")
	}

	// If authenticated, verify sender matches the auth user
	if s.authUser != nil {
		expectedAddr := s.authUser.Username + "@" + s.authUser.Domain
		fromClean := extractAddr(from)
		if !strings.EqualFold(fromClean, expectedAddr) {
			// Check if it's an alias owned by this user
			alias, err := s.db.ResolveAlias(fromClean)
			if err != nil || alias == nil || alias.UserID != s.authUser.ID {
				return fmt.Errorf("sender address not authorized")
			}
		}
	}

	s.from = from
	return nil
}

func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.to = append(s.to, to)
	return nil
}

func (s *Session) Data(r io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(r, s.cfg.SMTP.MaxMessageSize))
	if err != nil {
		return fmt.Errorf("reading message data: %w", err)
	}

	// For inbound (unauthenticated) messages: verify DKIM and add auth results
	if !s.requireAuth || s.authUser == nil {
		// Strip any existing Authentication-Results to prevent spoofing
		data = dkim.StripExistingAuthResults(data)

		// Verify DKIM signature
		auth := dkim.VerifyInbound(data)
		data = dkim.AddAuthResultsHeader(data, s.cfg.Server.Hostname, auth)
	}

	for _, rcpt := range s.to {
		addr := extractAddr(rcpt)
		if err := s.deliverMessage(addr, data); err != nil {
			s.logger.Error("delivery failed", "to", addr, "error", err)
			return fmt.Errorf("delivery failed")
		}
	}

	return nil
}

func (s *Session) deliverMessage(to string, data []byte) error {
	parts := strings.SplitN(to, "@", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid recipient address")
	}
	local, domain := parts[0], parts[1]

	// Check if this is a local domain
	isLocal, err := s.db.IsLocalDomain(domain)
	if err != nil {
		return fmt.Errorf("checking domain: %w", err)
	}

	if !isLocal {
		// Reject relay attempts from unauthenticated senders
		if s.authUser == nil {
			s.logger.Warn("rejected open relay attempt", "from", s.from, "to", to)
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 7, 1},
				Message:      "relaying denied: authentication required for external delivery",
			}
		}
		// Queue for outbound delivery
		return s.db.EnqueueMessage(s.from, to, data)
	}

	// Try direct user lookup
	user, err := s.db.GetUser(local, domain)
	if err != nil {
		return fmt.Errorf("looking up user: %w", err)
	}

	// Try alias resolution if not a direct user
	if user == nil {
		alias, err := s.db.ResolveAlias(to)
		if err != nil {
			return fmt.Errorf("resolving alias: %w", err)
		}
		if alias == nil {
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 1, 1},
				Message:      "user not found",
			}
		}
		if !alias.IsActive {
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 1, 1},
				Message:      "address no longer active",
			}
		}

		// Check expiry
		if alias.ExpiresAt != nil && alias.ExpiresAt.Before(time.Now()) {
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 1, 1},
				Message:      "address expired",
			}
		}

		// Check message limit
		if alias.MaxMessages != nil && alias.MessageCount >= *alias.MaxMessages {
			s.db.DeactivateAlias(alias.ID)
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 1, 1},
				Message:      "address message limit reached",
			}
		}

		// Increment alias counter
		s.db.IncrementAliasCount(alias.ID)

		user, err = s.db.GetUserByID(alias.UserID)
		if err != nil || user == nil {
			return fmt.Errorf("alias owner not found")
		}
	}

	// Deliver to user's INBOX
	inbox, err := s.db.GetMailbox(user.ID, "INBOX")
	if err != nil || inbox == nil {
		return fmt.Errorf("INBOX not found for user")
	}

	// Quota enforcement.
	// NOTE: There is a TOCTOU race between this check and the StoreMessage call
	// below. Two concurrent deliveries could both pass the check before either
	// inserts. SQLite's single-writer serialization mitigates the worst case,
	// but a proper fix would use BEGIN IMMEDIATE with an atomic
	// check-and-insert inside a single transaction.
	if user.QuotaBytes > 0 {
		usage, err := s.db.UserUsageBytes(user.ID)
		if err == nil && usage+int64(len(data)) > user.QuotaBytes {
			return &smtp.SMTPError{
				Code:         552,
				EnhancedCode: smtp.EnhancedCode{5, 2, 2},
				Message:      "mailbox quota exceeded",
			}
		}
	}

	// Parse expiry header if present
	expiresAt := parseExpiryHeader(data)

	msg := &storage.Message{
		MailboxID:    inbox.ID,
		Size:         len(data),
		InternalDate: time.Now(),
		ExpiresAt:    expiresAt,
	}

	// Separate headers and body for search indexing
	headerData, bodyData := splitMessage(data)

	// Envelope-encrypt the message if user has a public key
	if len(user.PublicKey) > 0 {
		bodyEnc, bodyNonce, wrappedKey, keyNonce, err := crypto.EncryptMessage(data, user.PublicKey)
		if err != nil {
			return fmt.Errorf("encrypting message: %w", err)
		}

		msg.BodyEnc = bodyEnc
		msg.BodyNonce = bodyNonce
		msg.MessageKeyEnc = wrappedKey
		msg.MessageKeyNonce = keyNonce

		// Encrypt headers separately
		if len(headerData) > 0 {
			headerEnc, headerNonce, _, _, err := crypto.EncryptMessage(headerData, user.PublicKey)
			if err == nil {
				msg.HeaderEnc = headerEnc
				msg.HeaderNonce = headerNonce
			}
		}
	} else {
		// No public key: store plaintext (legacy/migration path)
		msg.BodyEnc = data
	}

	if err := s.db.StoreMessage(msg); err != nil {
		return fmt.Errorf("storing message: %w", err)
	}

	// Generate blind search index tokens if the user has a search key
	if len(user.SearchKey) > 0 {
		subject, from, toAddr := extractHeaderFields(headerData)
		tokens := crypto.GenerateSearchTokens(user.SearchKey, subject, from, toAddr, string(bodyData))
		if len(tokens) > 0 {
			storageTokens := make([]storage.SearchToken, len(tokens))
			for i, t := range tokens {
				storageTokens[i] = storage.SearchToken{Hash: t.TokenHash, Field: t.Field}
			}
			s.db.StoreSearchTokens(msg.ID, storageTokens)
		}
	}

	s.logger.Info("message delivered", "to", to, "size", len(data), "uid", msg.UID, "encrypted", len(user.PublicKey) > 0)
	return nil
}

func (s *Session) Reset() {
	s.from = ""
	s.to = nil
}

func (s *Session) Logout() error {
	return nil
}

// extractAddr extracts the email address from a potentially angle-bracketed string.
// It rejects addresses containing CR, LF, or NUL to prevent CRLF injection attacks.
func extractAddr(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "<") && strings.HasSuffix(s, ">") {
		s = s[1 : len(s)-1]
	}
	// Reject addresses with CRLF injection or null bytes
	if strings.ContainsAny(s, "\r\n\x00") {
		return ""
	}
	return strings.ToLower(s)
}

// splitMessage separates RFC 5322 headers from body.
func splitMessage(data []byte) (headers, body []byte) {
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(data, sep)
	if idx == -1 {
		sep = []byte("\n\n")
		idx = bytes.Index(data, sep)
	}
	if idx == -1 {
		return data, nil
	}
	return data[:idx], data[idx+len(sep):]
}

// extractHeaderFields pulls Subject, From, To from raw header bytes.
func extractHeaderFields(headerData []byte) (subject, from, to string) {
	lines := strings.Split(string(headerData), "\n")
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "subject:") {
			subject = strings.TrimSpace(line[8:])
		} else if strings.HasPrefix(lower, "from:") {
			from = strings.TrimSpace(line[5:])
		} else if strings.HasPrefix(lower, "to:") {
			to = strings.TrimSpace(line[3:])
		}
	}
	return
}

// encryptWithMessageKey is a convenience for encrypting additional fields.
// It generates a new per-field key using the same pattern.
func encryptWithMessageKey(data, wrappedKey, keyNonce, publicKey []byte) ([]byte, []byte, error) {
	if len(data) == 0 {
		return nil, nil, nil
	}
	ct, nonce, _, _, err := crypto.EncryptMessage(data, publicKey)
	if err != nil {
		return nil, nil, err
	}
	return ct, nonce, nil
}

// parseExpiryHeader checks for X-GhostMail-Expires or X-GhostMail-Expires-At headers.
// X-GhostMail-Expires: 3600       (seconds from now)
// X-GhostMail-Expires-At: 2026-01-01T00:00:00Z  (RFC3339 absolute time)
func parseExpiryHeader(data []byte) *time.Time {
	headerData, _ := splitMessage(data)
	lines := strings.Split(string(headerData), "\n")

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		lower := strings.ToLower(line)

		if strings.HasPrefix(lower, "x-ghostmail-expires-at:") {
			val := strings.TrimSpace(line[len("x-ghostmail-expires-at:"):])
			if t, err := time.Parse(time.RFC3339, val); err == nil {
				return &t
			}
		} else if strings.HasPrefix(lower, "x-ghostmail-expires:") {
			val := strings.TrimSpace(line[len("x-ghostmail-expires:"):])
			var seconds int64
			if _, err := fmt.Sscanf(val, "%d", &seconds); err == nil && seconds > 0 {
				t := time.Now().Add(time.Duration(seconds) * time.Second)
				return &t
			}
		}
	}
	return nil
}
