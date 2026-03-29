package webmail

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ghostmail/ghostmail/internal/crypto"
)

type searchRequest struct {
	Query   string `json:"query"`
	Mailbox string `json:"mailbox"`
}

func (h *Handler) handleSearch(w http.ResponseWriter, r *http.Request) {
	sess := h.sessions.GetFromRequest(r)

	var req searchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}

	if req.Query == "" {
		jsonError(w, "query is required", http.StatusBadRequest)
		return
	}

	if sess.Keys == nil || sess.Keys.SearchKey == nil {
		jsonError(w, "search unavailable", http.StatusServiceUnavailable)
		return
	}

	// Tokenize and compute search hashes
	terms := tokenize(req.Query)
	if len(terms) == 0 {
		jsonResponse(w, map[string]interface{}{"messages": []interface{}{}, "total": 0})
		return
	}

	tokenHashes := make([][]byte, 0, len(terms))
	for _, term := range terms {
		hash := crypto.ComputeSearchQuery(sess.Keys.SearchKey, term)
		tokenHashes = append(tokenHashes, hash)
	}

	// AND-search: find messages matching all tokens
	messageIDs, err := h.db.SearchByTokens(tokenHashes)
	if err != nil {
		jsonError(w, "search failed", http.StatusInternalServerError)
		return
	}

	// Get user's mailboxes for filtering and validation
	mailboxes, _ := h.db.ListMailboxes(sess.UserID)
	mbMap := make(map[int64]string)
	var filterMbID int64
	for _, mb := range mailboxes {
		mbMap[mb.ID] = mb.Name
		if req.Mailbox != "" && mb.Name == req.Mailbox {
			filterMbID = mb.ID
		}
	}

	// Fetch message details
	results := make([]map[string]interface{}, 0)
	for _, msgID := range messageIDs {
		msg, err := h.db.GetMessageByID(msgID)
		if err != nil || msg == nil {
			continue
		}

		// Verify this message belongs to the user
		mbName, ok := mbMap[msg.MailboxID]
		if !ok {
			continue
		}

		// Apply mailbox filter
		if filterMbID > 0 && msg.MailboxID != filterMbID {
			continue
		}

		from, to, subject, date := extractMessageSummary(msg, sess.Keys)
		results = append(results, map[string]interface{}{
			"uid":       msg.UID,
			"mailboxID": msg.MailboxID,
			"mailbox":   mbName,
			"from":      from,
			"to":        to,
			"subject":   subject,
			"date":      date,
			"flags":     msg.Flags,
			"size":      msg.Size,
		})

		if len(results) >= 50 {
			break
		}
	}

	jsonResponse(w, map[string]interface{}{
		"messages": results,
		"total":    len(results),
		"query":    req.Query,
	})
}

// tokenize splits text into normalized search terms.
func tokenize(text string) []string {
	text = strings.ToLower(text)
	// Split on whitespace and punctuation
	words := strings.FieldsFunc(text, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	})

	// Remove stop words and deduplicate
	stopWords := map[string]bool{
		"the": true, "a": true, "an": true, "and": true, "or": true,
		"is": true, "are": true, "was": true, "were": true, "be": true,
		"to": true, "of": true, "in": true, "for": true, "on": true,
		"with": true, "at": true, "by": true, "it": true, "this": true,
		"that": true, "from": true, "not": true, "but": true, "has": true,
	}

	seen := make(map[string]bool)
	var result []string
	for _, w := range words {
		if len(w) < 2 || stopWords[w] || seen[w] {
			continue
		}
		seen[w] = true
		result = append(result, w)
	}
	return result
}
