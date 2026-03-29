package webmail

import (
	cryptoRand "crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/ghostmail/ghostmail/internal/crypto"
	"github.com/ghostmail/ghostmail/internal/storage"
)

type composeRequest struct {
	To        string `json:"to"`
	CC        string `json:"cc"`
	BCC       string `json:"bcc"`
	Subject   string `json:"subject"`
	Body      string `json:"body"`
	FromAlias string `json:"from_alias"`
	InReplyTo string `json:"in_reply_to"`
}

// buildRFC5322 constructs a complete RFC 5322 email message from compose fields.
func buildRFC5322(from, to, cc, subject, body, inReplyTo, hostname string) []byte {
	var b strings.Builder
	msgID := fmt.Sprintf("<%d.%s@%s>", time.Now().UnixNano(), randomHex(8), hostname)

	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	if cc != "" {
		b.WriteString("Cc: " + cc + "\r\n")
	}
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("Date: " + time.Now().Format("Mon, 02 Jan 2006 15:04:05 -0700") + "\r\n")
	b.WriteString("Message-ID: " + msgID + "\r\n")
	if inReplyTo != "" {
		b.WriteString("In-Reply-To: " + inReplyTo + "\r\n")
		b.WriteString("References: " + inReplyTo + "\r\n")
	}
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)

	return []byte(b.String())
}

// deliverLocal encrypts and stores a message for a local user.
func (h *Handler) deliverLocal(user *storage.User, rawMessage []byte) error {
	inbox, err := h.db.GetMailbox(user.ID, "INBOX")
	if err != nil || inbox == nil {
		return fmt.Errorf("INBOX not found for user")
	}

	msg := &storage.Message{
		MailboxID:    inbox.ID,
		Size:         len(rawMessage),
		InternalDate: time.Now(),
	}

	// Envelope-encrypt if user has a public key
	if len(user.PublicKey) > 0 {
		bodyEnc, bodyNonce, wrappedKey, keyNonce, err := crypto.EncryptMessage(rawMessage, user.PublicKey)
		if err != nil {
			return fmt.Errorf("encrypting message: %w", err)
		}
		msg.BodyEnc = bodyEnc
		msg.BodyNonce = bodyNonce
		msg.MessageKeyEnc = wrappedKey
		msg.MessageKeyNonce = keyNonce
	} else {
		msg.BodyEnc = rawMessage
	}

	if err := h.db.StoreMessage(msg); err != nil {
		return fmt.Errorf("storing message: %w", err)
	}

	// Generate blind search index tokens
	if len(user.SearchKey) > 0 {
		headerData, bodyData := splitMessage(rawMessage)
		from, to, subject := parseHeaderFields(headerData)
		tokens := crypto.GenerateSearchTokens(user.SearchKey, subject, from, to, string(bodyData))
		if len(tokens) > 0 {
			storageTokens := make([]storage.SearchToken, len(tokens))
			for i, t := range tokens {
				storageTokens[i] = storage.SearchToken{Hash: t.TokenHash, Field: t.Field}
			}
			h.db.StoreSearchTokens(msg.ID, storageTokens)
		}
	}

	return nil
}

// storeSentCopy encrypts and stores a copy in the sender's Sent mailbox.
func (h *Handler) storeSentCopy(user *storage.User, rawMessage []byte) {
	sent, err := h.db.GetMailbox(user.ID, "Sent")
	if err != nil || sent == nil {
		return
	}

	msg := &storage.Message{
		MailboxID:    sent.ID,
		Size:         len(rawMessage),
		Flags:        "\\Seen",
		InternalDate: time.Now(),
	}

	if len(user.PublicKey) > 0 {
		bodyEnc, bodyNonce, wrappedKey, keyNonce, err := crypto.EncryptMessage(rawMessage, user.PublicKey)
		if err != nil {
			return
		}
		msg.BodyEnc = bodyEnc
		msg.BodyNonce = bodyNonce
		msg.MessageKeyEnc = wrappedKey
		msg.MessageKeyNonce = keyNonce
	} else {
		msg.BodyEnc = rawMessage
	}

	h.db.StoreMessage(msg)
}

func randomHex(n int) string {
	b := make([]byte, n)
	cryptoRand.Read(b)
	return fmt.Sprintf("%x", b)
}
