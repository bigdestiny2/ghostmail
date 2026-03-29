package webmail

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/ghostmail/ghostmail/internal/crypto"
	"github.com/ghostmail/ghostmail/internal/storage"
)

type fullMessage struct {
	UID      int    `json:"uid"`
	From     string `json:"from"`
	To       string `json:"to"`
	CC       string `json:"cc"`
	Subject  string `json:"subject"`
	Date     string `json:"date"`
	BodyText string `json:"body_text"`
	BodyHTML string `json:"body_html"`
	Flags    string `json:"flags"`
	Size     int    `json:"size"`
}

func (h *Handler) handleGetMessage(w http.ResponseWriter, r *http.Request) {
	sess := h.sessions.GetFromRequest(r)
	mailboxID, _ := strconv.ParseInt(r.PathValue("mailboxID"), 10, 64)
	uid, _ := strconv.Atoi(r.PathValue("uid"))

	if mailboxID == 0 || uid == 0 {
		jsonError(w, "invalid parameters", http.StatusBadRequest)
		return
	}

	// Verify the mailbox belongs to this user
	mailboxes, err := h.db.ListMailboxes(sess.UserID)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	var ownsMailbox bool
	for _, mb := range mailboxes {
		if mb.ID == mailboxID {
			ownsMailbox = true
			break
		}
	}
	if !ownsMailbox {
		jsonError(w, "mailbox not found", http.StatusNotFound)
		return
	}

	msg, err := h.db.GetMessage(mailboxID, uid)
	if err != nil || msg == nil {
		jsonError(w, "message not found", http.StatusNotFound)
		return
	}

	// Decrypt
	var plaintext []byte
	if sess.Keys != nil && len(msg.MessageKeyEnc) > 0 {
		plaintext, err = crypto.DecryptMessage(
			msg.BodyEnc, msg.BodyNonce,
			msg.MessageKeyEnc, msg.MessageKeyNonce,
			sess.Keys.PrivateKey,
		)
		if err != nil {
			h.logger.Error("message decryption failed", "uid", uid, "error", err)
			jsonError(w, "decryption failed", http.StatusInternalServerError)
			return
		}
	} else {
		plaintext = msg.BodyEnc
	}

	// Parse the decrypted RFC 5322 message
	headerData, bodyData := splitMessage(plaintext)
	from, to, subject := parseHeaderFields(headerData)
	cc := parseHeaderField(headerData, "cc")

	// Mark as read
	if !storage.HasFlag(msg.Flags, "\\Seen") {
		newFlags := storage.AddFlag(msg.Flags, "\\Seen")
		h.db.UpdateFlags(msg.ID, newFlags)
		msg.Flags = newFlags
	}

	bodyText := string(bodyData)
	bodyHTML := ""

	// Check if this is a multipart message with HTML
	contentType := parseHeaderField(headerData, "content-type")
	if strings.Contains(strings.ToLower(contentType), "text/html") {
		bodyHTML = bodyText
		bodyText = ""
	}

	jsonResponse(w, fullMessage{
		UID:      msg.UID,
		From:     from,
		To:       to,
		CC:       cc,
		Subject:  subject,
		Date:     msg.InternalDate.Format("2006-01-02 15:04:05"),
		BodyText: bodyText,
		BodyHTML: bodyHTML,
		Flags:    msg.Flags,
		Size:     msg.Size,
	})
}

type flagsRequest struct {
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
}

func (h *Handler) handleUpdateFlags(w http.ResponseWriter, r *http.Request) {
	sess := h.sessions.GetFromRequest(r)
	mailboxID, _ := strconv.ParseInt(r.PathValue("mailboxID"), 10, 64)
	uid, _ := strconv.Atoi(r.PathValue("uid"))

	if !h.userOwnsMailbox(sess.UserID, mailboxID) {
		jsonError(w, "mailbox not found", http.StatusNotFound)
		return
	}

	msg, err := h.db.GetMessage(mailboxID, uid)
	if err != nil || msg == nil {
		jsonError(w, "message not found", http.StatusNotFound)
		return
	}

	var req flagsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}

	flags := msg.Flags
	for _, f := range req.Add {
		flags = storage.AddFlag(flags, f)
	}
	for _, f := range req.Remove {
		flags = storage.RemoveFlag(flags, f)
	}

	if err := h.db.UpdateFlags(msg.ID, flags); err != nil {
		jsonError(w, "failed to update flags", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]string{"flags": flags})
}

type moveRequest struct {
	Destination string `json:"destination"`
}

func (h *Handler) handleMoveMessage(w http.ResponseWriter, r *http.Request) {
	sess := h.sessions.GetFromRequest(r)
	mailboxID, _ := strconv.ParseInt(r.PathValue("mailboxID"), 10, 64)
	uid, _ := strconv.Atoi(r.PathValue("uid"))

	if !h.userOwnsMailbox(sess.UserID, mailboxID) {
		jsonError(w, "mailbox not found", http.StatusNotFound)
		return
	}

	var req moveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}

	destMb, err := h.db.GetMailbox(sess.UserID, req.Destination)
	if err != nil || destMb == nil {
		jsonError(w, "destination mailbox not found", http.StatusNotFound)
		return
	}

	msg, err := h.db.GetMessage(mailboxID, uid)
	if err != nil || msg == nil {
		jsonError(w, "message not found", http.StatusNotFound)
		return
	}

	if err := h.db.MoveMessage(msg.ID, destMb.ID); err != nil {
		jsonError(w, "failed to move message", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]bool{"ok": true})
}

func (h *Handler) handleDeleteMessage(w http.ResponseWriter, r *http.Request) {
	sess := h.sessions.GetFromRequest(r)
	mailboxID, _ := strconv.ParseInt(r.PathValue("mailboxID"), 10, 64)
	uid, _ := strconv.Atoi(r.PathValue("uid"))

	if !h.userOwnsMailbox(sess.UserID, mailboxID) {
		jsonError(w, "mailbox not found", http.StatusNotFound)
		return
	}

	msg, err := h.db.GetMessage(mailboxID, uid)
	if err != nil || msg == nil {
		jsonError(w, "message not found", http.StatusNotFound)
		return
	}

	// Check if already in Trash — if so, permanent delete
	mailboxes, _ := h.db.ListMailboxes(sess.UserID)
	var trashMb *storage.Mailbox
	var currentMbName string
	for _, mb := range mailboxes {
		if mb.SpecialUse == "\\Trash" || mb.Name == "Trash" {
			trashMb = mb
		}
		if mb.ID == mailboxID {
			currentMbName = mb.Name
		}
	}

	if currentMbName == "Trash" || (trashMb != nil && mailboxID == trashMb.ID) {
		// Permanent delete
		h.db.DeleteSearchTokens(msg.ID)
		if err := h.db.DeleteMessage(msg.ID); err != nil {
			jsonError(w, "failed to delete message", http.StatusInternalServerError)
			return
		}
	} else if trashMb != nil {
		// Move to Trash
		if err := h.db.MoveMessage(msg.ID, trashMb.ID); err != nil {
			jsonError(w, "failed to move to trash", http.StatusInternalServerError)
			return
		}
	} else {
		// No Trash mailbox; permanent delete
		h.db.DeleteSearchTokens(msg.ID)
		if err := h.db.DeleteMessage(msg.ID); err != nil {
			jsonError(w, "failed to delete message", http.StatusInternalServerError)
			return
		}
	}

	jsonResponse(w, map[string]bool{"ok": true})
}

func (h *Handler) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	sess := h.sessions.GetFromRequest(r)

	var req composeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}

	if req.To == "" || req.Subject == "" {
		jsonError(w, "to and subject are required", http.StatusBadRequest)
		return
	}

	sender, err := h.db.GetUser(sess.Username, sess.Domain)
	if err != nil || sender == nil {
		jsonError(w, "sender not found", http.StatusInternalServerError)
		return
	}

	fromAddr := sess.Username + "@" + sess.Domain
	if req.FromAlias != "" {
		// Verify alias ownership
		alias, err := h.db.ResolveAlias(req.FromAlias)
		if err == nil && alias != nil && alias.UserID == sess.UserID {
			fromAddr = req.FromAlias
		}
	}

	// Build the RFC 5322 message
	rawMessage := buildRFC5322(fromAddr, req.To, req.CC, req.Subject, req.Body, req.InReplyTo, h.cfg.Server.Hostname)

	// Collect all recipients (To + CC + BCC)
	allRecipients := parseRecipients(req.To)
	allRecipients = append(allRecipients, parseRecipients(req.CC)...)
	allRecipients = append(allRecipients, parseRecipients(req.BCC)...)

	var deliveryErrors []string
	for _, rcpt := range allRecipients {
		rcpt = strings.TrimSpace(rcpt)
		if rcpt == "" {
			continue
		}

		parts := strings.SplitN(rcpt, "@", 2)
		if len(parts) != 2 {
			deliveryErrors = append(deliveryErrors, rcpt+": invalid address")
			continue
		}

		isLocal, _ := h.db.IsLocalDomain(parts[1])
		if isLocal {
			// Local delivery
			user, err := h.db.GetUser(parts[0], parts[1])
			if err != nil || user == nil {
				// Try alias
				alias, err := h.db.ResolveAlias(rcpt)
				if err != nil || alias == nil {
					deliveryErrors = append(deliveryErrors, rcpt+": user not found")
					continue
				}
				user, err = h.db.GetUserByID(alias.UserID)
				if err != nil || user == nil {
					deliveryErrors = append(deliveryErrors, rcpt+": alias owner not found")
					continue
				}
			}
			if err := h.deliverLocal(user, rawMessage); err != nil {
				deliveryErrors = append(deliveryErrors, rcpt+": "+err.Error())
			}
		} else {
			// External — queue for outbound delivery
			if err := h.db.EnqueueMessage(fromAddr, rcpt, rawMessage); err != nil {
				deliveryErrors = append(deliveryErrors, rcpt+": queue error")
			}
		}
	}

	// Store copy in Sent
	h.storeSentCopy(sender, rawMessage)

	if len(deliveryErrors) > 0 {
		jsonResponse(w, map[string]interface{}{
			"ok":     false,
			"errors": deliveryErrors,
		})
		return
	}

	h.logger.Info("webmail send", "from", fromAddr, "recipients", len(allRecipients))
	jsonResponse(w, map[string]bool{"ok": true})
}

func parseRecipients(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		addr := strings.TrimSpace(p)
		// Extract email from "Name <email>" format
		if idx := strings.Index(addr, "<"); idx >= 0 {
			end := strings.Index(addr, ">")
			if end > idx {
				addr = addr[idx+1 : end]
			}
		}
		addr = strings.ToLower(strings.TrimSpace(addr))
		if addr != "" {
			result = append(result, addr)
		}
	}
	return result
}

// --- Helpers ---

func (h *Handler) userOwnsMailbox(userID, mailboxID int64) bool {
	mailboxes, err := h.db.ListMailboxes(userID)
	if err != nil {
		return false
	}
	for _, mb := range mailboxes {
		if mb.ID == mailboxID {
			return true
		}
	}
	return false
}

func parseHeaderField(headerData []byte, field string) string {
	prefix := strings.ToLower(field) + ":"
	lines := strings.Split(string(headerData), "\n")
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(strings.ToLower(line), prefix) {
			return strings.TrimSpace(line[len(prefix):])
		}
	}
	return ""
}
