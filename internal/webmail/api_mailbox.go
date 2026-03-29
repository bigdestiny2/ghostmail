package webmail

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/ghostmail/ghostmail/internal/crypto"
	"github.com/ghostmail/ghostmail/internal/storage"
)

type mailboxInfo struct {
	Name       string `json:"name"`
	Total      int    `json:"total"`
	Unread     int    `json:"unread"`
	SpecialUse string `json:"specialUse"`
}

func (h *Handler) handleListMailboxes(w http.ResponseWriter, r *http.Request) {
	sess := h.sessions.GetFromRequest(r)

	mailboxes, err := h.db.ListMailboxes(sess.UserID)
	if err != nil {
		jsonError(w, "failed to list mailboxes", http.StatusInternalServerError)
		return
	}

	result := make([]mailboxInfo, 0, len(mailboxes))
	for _, mb := range mailboxes {
		total, _ := h.db.MailboxMessageCount(mb.ID)
		unread, _ := h.db.MailboxUnreadCount(mb.ID)
		result = append(result, mailboxInfo{
			Name:       mb.Name,
			Total:      total,
			Unread:     unread,
			SpecialUse: mb.SpecialUse,
		})
	}

	jsonResponse(w, result)
}

type messageSummary struct {
	UID     int    `json:"uid"`
	From    string `json:"from"`
	To      string `json:"to"`
	Subject string `json:"subject"`
	Date    string `json:"date"`
	Flags   string `json:"flags"`
	Size    int    `json:"size"`
	Unread  bool   `json:"unread"`
}

func (h *Handler) handleListMessages(w http.ResponseWriter, r *http.Request) {
	sess := h.sessions.GetFromRequest(r)
	mbName := r.PathValue("name")

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 100 {
		limit = 50
	}

	mb, err := h.db.GetMailbox(sess.UserID, mbName)
	if err != nil || mb == nil {
		jsonError(w, "mailbox not found", http.StatusNotFound)
		return
	}

	offset := (page - 1) * limit
	messages, err := h.db.ListMessagesPaginated(mb.ID, limit, offset)
	if err != nil {
		jsonError(w, "failed to list messages", http.StatusInternalServerError)
		return
	}

	total, _ := h.db.MailboxMessageCount(mb.ID)

	summaries := make([]messageSummary, 0, len(messages))
	for _, msg := range messages {
		from, to, subject, date := extractMessageSummary(msg, sess.Keys)
		summaries = append(summaries, messageSummary{
			UID:     msg.UID,
			From:    from,
			To:      to,
			Subject: subject,
			Date:    date,
			Flags:   msg.Flags,
			Size:    msg.Size,
			Unread:  !storage.HasFlag(msg.Flags, "\\Seen"),
		})
	}

	jsonResponse(w, map[string]interface{}{
		"messages": summaries,
		"total":    total,
		"page":     page,
		"limit":    limit,
		"mailbox":  mbName,
	})
}

// extractMessageSummary decrypts headers to get from/to/subject/date for list view.
func extractMessageSummary(msg *storage.Message, keys *crypto.SessionKeys) (from, to, subject, date string) {
	date = msg.InternalDate.Format("2006-01-02 15:04")

	// Try to decrypt the full message body (which contains headers) for header extraction
	var headerData []byte
	if keys != nil && len(msg.MessageKeyEnc) > 0 {
		plaintext, err := crypto.DecryptMessage(
			msg.BodyEnc, msg.BodyNonce,
			msg.MessageKeyEnc, msg.MessageKeyNonce,
			keys.PrivateKey,
		)
		if err == nil {
			// Extract headers from the decrypted RFC 5322 message
			headerData, _ = splitMessage(plaintext)
		}
	} else if len(msg.BodyEnc) > 0 {
		// Unencrypted legacy message
		headerData, _ = splitMessage(msg.BodyEnc)
	}

	if len(headerData) > 0 {
		from, to, subject = parseHeaderFields(headerData)
	}

	if from == "" {
		from = "(encrypted)"
	}
	if subject == "" {
		subject = "(no subject)"
	}
	return
}

// splitMessage separates RFC 5322 headers from body.
func splitMessage(data []byte) (headers, body []byte) {
	// Look for \r\n\r\n first, then \n\n
	for i := 0; i < len(data)-3; i++ {
		if data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n' {
			return data[:i], data[i+4:]
		}
	}
	for i := 0; i < len(data)-1; i++ {
		if data[i] == '\n' && data[i+1] == '\n' {
			return data[:i], data[i+2:]
		}
	}
	return data, nil
}

// parseHeaderFields extracts Subject, From, To from raw header bytes.
func parseHeaderFields(headerData []byte) (from, to, subject string) {
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
