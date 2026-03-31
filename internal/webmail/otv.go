package webmail

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"net/http"
	"sync"
	"time"

	"github.com/ghostmail/ghostmail/internal/crypto"
)

const (
	otvTTL       = 5 * time.Minute
	otvMaxActive = 100 // max OTV tokens per user
)

// otvEntry holds a decrypted message for one-time viewing.
type otvEntry struct {
	Message   *otvMessage
	UserID    int64
	CreatedAt time.Time
	Viewed    bool
}

// otvMessage is the decrypted message content stored in RAM.
type otvMessage struct {
	From    string `json:"from"`
	To      string `json:"to"`
	CC      string `json:"cc"`
	Subject string `json:"subject"`
	Date    string `json:"date"`
	Body    string `json:"body"`
}

// OTVStore manages one-time-view tokens in memory.
type OTVStore struct {
	mu      sync.Mutex
	entries map[string]*otvEntry
}

func NewOTVStore() *OTVStore {
	return &OTVStore{
		entries: make(map[string]*otvEntry),
	}
}

// Create generates a new OTV token and stores the decrypted message.
func (s *OTVStore) Create(userID int64, msg *otvMessage) string {
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)

	s.mu.Lock()
	s.entries[token] = &otvEntry{
		Message:   msg,
		UserID:    userID,
		CreatedAt: time.Now(),
	}
	s.mu.Unlock()

	return token
}

// View retrieves and deletes an OTV entry (single use).
// Returns nil if token is invalid, expired, or already viewed.
func (s *OTVStore) View(token string) *otvMessage {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[token]
	if !ok {
		return nil
	}

	// Check expiry
	if time.Since(entry.CreatedAt) > otvTTL {
		delete(s.entries, token)
		return nil
	}

	// Check already viewed
	if entry.Viewed {
		delete(s.entries, token)
		return nil
	}

	// Mark viewed and delete
	msg := entry.Message
	entry.Message = nil
	entry.Viewed = true
	delete(s.entries, token)

	return msg
}

// Sweep removes expired entries. Called periodically.
func (s *OTVStore) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for token, entry := range s.entries {
		if now.Sub(entry.CreatedAt) > otvTTL {
			entry.Message = nil // clear from memory
			delete(s.entries, token)
		}
	}
}

// CountForUser returns the number of active OTV tokens for a user.
func (s *OTVStore) CountForUser(userID int64) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for _, entry := range s.entries {
		if entry.UserID == userID {
			count++
		}
	}
	return count
}

// StartSweeper runs periodic cleanup of expired OTV tokens.
func (s *OTVStore) StartSweeper(stop <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.Sweep()
			case <-stop:
				return
			}
		}
	}()
}

// --- HTTP Handlers ---

// handleCreateOTV creates a one-time view link for a message.
// POST /api/v1/otv/create  { "mailbox_id": 1, "uid": 5 }
func (h *Handler) handleCreateOTV(w http.ResponseWriter, r *http.Request) {
	sess := h.sessions.GetFromRequest(r)

	var req struct {
		MailboxID int64 `json:"mailbox_id"`
		UID       int   `json:"uid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.MailboxID == 0 || req.UID == 0 {
		jsonError(w, "mailbox_id and uid are required", http.StatusBadRequest)
		return
	}

	// Verify mailbox ownership
	if !h.userOwnsMailbox(sess.UserID, req.MailboxID) {
		jsonError(w, "mailbox not found", http.StatusNotFound)
		return
	}

	// Rate limit: max active OTV per user
	if h.otv.CountForUser(sess.UserID) >= otvMaxActive {
		jsonError(w, "too many active view links", http.StatusTooManyRequests)
		return
	}

	// Fetch and decrypt message
	msg, err := h.db.GetMessage(req.MailboxID, req.UID)
	if err != nil || msg == nil {
		jsonError(w, "message not found", http.StatusNotFound)
		return
	}

	var plaintext []byte
	if sess.Keys != nil && len(msg.MessageKeyEnc) > 0 {
		plaintext, err = crypto.DecryptMessage(
			msg.BodyEnc, msg.BodyNonce,
			msg.MessageKeyEnc, msg.MessageKeyNonce,
			sess.Keys.PrivateKey,
		)
		if err != nil {
			jsonError(w, "decryption failed - vault may be locked", http.StatusForbidden)
			return
		}
	} else if sess.Keys == nil && len(msg.MessageKeyEnc) > 0 {
		jsonError(w, "vault is locked - unlock to create view links", http.StatusForbidden)
		return
	} else {
		plaintext = msg.BodyEnc
	}

	// Parse RFC 5322
	headerData, bodyData := splitMessage(plaintext)
	from, to, subject := parseHeaderFields(headerData)
	cc := parseHeaderField(headerData, "cc")

	otvMsg := &otvMessage{
		From:    from,
		To:      to,
		CC:      cc,
		Subject: subject,
		Date:    msg.InternalDate.Format("2006-01-02 15:04:05"),
		Body:    string(bodyData),
	}

	token := h.otv.Create(sess.UserID, otvMsg)

	// Build the full URL
	scheme := "https"
	host := r.Host
	if host == "" {
		host = h.cfg.Server.Hostname
	}
	viewURL := scheme + "://" + host + "/mail/view/" + token

	expiresAt := time.Now().Add(otvTTL)

	jsonResponse(w, map[string]interface{}{
		"url":        viewURL,
		"token":      token,
		"expires_at": expiresAt.Format(time.RFC3339),
		"expires_in": int(otvTTL.Seconds()),
	})
}

// handleViewOTV renders a one-time view page. No auth required — the token IS the auth.
// GET /mail/view/{token}
func (h *Handler) handleViewOTV(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if token == "" || len(token) != 64 {
		h.renderOTVError(w, "Invalid link", "This link is not valid.")
		return
	}

	msg := h.otv.View(token)
	if msg == nil {
		h.renderOTVError(w, "Link Expired", "This message link has expired or has already been viewed. One-time view links can only be opened once and expire after 5 minutes.")
		return
	}

	// Set security headers — no caching
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:")

	h.templates["otv_view"].Execute(w, msg)
}

func (h *Handler) renderOTVError(w http.ResponseWriter, title, message string) {
	w.Header().Set("Cache-Control", "no-store")
	h.templates["otv_error"].Execute(w, map[string]string{
		"Title":   title,
		"Message": message,
	})
}

// otvViewTemplate returns the HTML template for the OTV view page.
var otvViewTemplate = template.Must(template.New("otv_view").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GhostMail - Secure Message</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117; color: #c9d1d9;
            display: flex; justify-content: center;
            padding: 2rem 1rem; min-height: 100vh;
        }
        .container { max-width: 700px; width: 100%; }
        .badge {
            display: inline-flex; align-items: center; gap: 0.5rem;
            background: #1a2332; border: 1px solid #f0883e;
            border-radius: 6px; padding: 0.5rem 1rem;
            font-size: 0.85rem; color: #f0883e; margin-bottom: 1.5rem;
        }
        .badge svg { width: 16px; height: 16px; fill: #f0883e; }
        .card {
            background: #161b22; border: 1px solid #30363d;
            border-radius: 8px; overflow: hidden;
        }
        .card-header {
            padding: 1.25rem 1.5rem; border-bottom: 1px solid #30363d;
        }
        .subject { font-size: 1.2rem; font-weight: 600; color: #f0f6fc; margin-bottom: 1rem; }
        .meta { display: grid; grid-template-columns: auto 1fr; gap: 0.25rem 1rem; font-size: 0.9rem; }
        .meta dt { color: #8b949e; font-weight: 500; }
        .meta dd { color: #c9d1d9; }
        .card-body {
            padding: 1.5rem; font-size: 0.95rem;
            line-height: 1.6; white-space: pre-wrap;
            word-wrap: break-word; min-height: 100px;
        }
        .footer {
            margin-top: 1.5rem; text-align: center;
            font-size: 0.8rem; color: #484f58;
        }
        .footer a { color: #58a6ff; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="badge">
            <svg viewBox="0 0 16 16"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zM0 8a8 8 0 1116 0A8 8 0 010 8zm9-3a1 1 0 11-2 0 1 1 0 012 0zM8 6.5a.75.75 0 01.75.75v4a.75.75 0 01-1.5 0v-4A.75.75 0 018 6.5z"/></svg>
            One-time view — this message will not be available again
        </div>
        <div class="card">
            <div class="card-header">
                <div class="subject">{{.Subject}}</div>
                <dl class="meta">
                    <dt>From</dt><dd>{{.From}}</dd>
                    <dt>To</dt><dd>{{.To}}</dd>
                    {{if .CC}}<dt>CC</dt><dd>{{.CC}}</dd>{{end}}
                    <dt>Date</dt><dd>{{.Date}}</dd>
                </dl>
            </div>
            <div class="card-body">{{.Body}}</div>
        </div>
        <div class="footer">
            Secured by <a href="#">GhostMail</a> — zero-knowledge encrypted email
        </div>
    </div>
</body>
</html>`))

var otvErrorTemplate = template.Must(template.New("otv_error").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GhostMail - Link Expired</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117; color: #c9d1d9;
            display: flex; justify-content: center; align-items: center;
            min-height: 100vh; padding: 2rem;
        }
        .container { max-width: 500px; text-align: center; }
        .icon { font-size: 3rem; margin-bottom: 1rem; }
        h1 { font-size: 1.4rem; color: #f0f6fc; margin-bottom: 0.75rem; }
        p { font-size: 0.95rem; color: #8b949e; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🔒</div>
        <h1>{{.Title}}</h1>
        <p>{{.Message}}</p>
    </div>
</body>
</html>`))
