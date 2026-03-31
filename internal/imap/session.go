package imap

import (
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/ghostmail/ghostmail/internal/config"
	"github.com/ghostmail/ghostmail/internal/crypto"
	"github.com/ghostmail/ghostmail/internal/storage"
	"github.com/ghostmail/ghostmail/internal/vault"
)

// Session implements imapserver.Session for a single IMAP connection.
type Session struct {
	server     *Server
	db         *storage.DB
	cfg        *config.Config
	logger     *slog.Logger
	vaultStore *vault.Store

	// Set after Login
	user        *storage.User
	sessionKeys *crypto.SessionKeys // Decryption keys held during session

	// Set after Select
	selectedMailbox *storage.Mailbox
	sessionTracker  *imapserver.SessionTracker
}

// Compile-time check that Session implements the required interfaces.
var _ imapserver.Session = (*Session)(nil)
var _ imapserver.SessionNamespace = (*Session)(nil)
var _ imapserver.SessionMove = (*Session)(nil)

func (s *Session) Close() error {
	if s.sessionTracker != nil {
		s.sessionTracker.Close()
		s.sessionTracker = nil
	}
	// Wipe session keys from memory
	if s.sessionKeys != nil {
		s.sessionKeys.Release()
		s.sessionKeys = nil
	}
	s.selectedMailbox = nil
	s.user = nil
	return nil
}

// --- Not Authenticated State ---

func (s *Session) Login(username, password string) error {
	parts := strings.SplitN(username, "@", 2)
	if len(parts) != 2 {
		return imapserver.ErrAuthFailed
	}
	local, domain := parts[0], parts[1]

	user, err := s.db.GetUser(local, domain)
	if err != nil {
		s.logger.Error("IMAP login lookup error", "error", err)
		return imapserver.ErrAuthFailed
	}
	if user == nil {
		return imapserver.ErrAuthFailed
	}

	// Vault-enabled user: auth password only proves identity, no key derivation
	if user.IsVaultUser() {
		authHash, err := hex.DecodeString(user.PasswordHash)
		if err != nil {
			return imapserver.ErrAuthFailed
		}
		if err := s.server.cryptoSvc.AuthenticateAuthOnly(
			[]byte(password), user.KeyParams, authHash,
		); err != nil {
			return imapserver.ErrAuthFailed
		}
		// Check if vault is already unlocked
		if s.vaultStore != nil {
			if vs := s.vaultStore.GetByUser(user.ID); vs != nil {
				s.sessionKeys = vs.Keys
			}
		}
		// sessionKeys may be nil — vault is locked. FETCH will return encrypted blobs.
	} else if len(user.WrappedPrivateKey) > 0 && user.KeyParams != "{}" {
		// Legacy single-password user: auth + decrypt in one step
		authHash, err := hex.DecodeString(user.PasswordHash)
		if err != nil {
			return imapserver.ErrAuthFailed
		}
		sk, err := s.server.cryptoSvc.Authenticate(
			[]byte(password), user.KeyParams, authHash,
			user.WrappedPrivateKey, user.KeyNonce,
		)
		if err != nil {
			return imapserver.ErrAuthFailed
		}
		s.sessionKeys = sk
	} else {
		// Legacy user without encryption keys: plain password check
		if user.PasswordHash != password {
			return imapserver.ErrAuthFailed
		}
	}

	s.user = user
	s.logger.Info("IMAP login", "user", username, "vault", user.IsVaultUser(), "unlocked", s.sessionKeys != nil)
	return nil
}

// --- Authenticated State ---

func (s *Session) Select(mailbox string, options *imap.SelectOptions) (*imap.SelectData, error) {
	if s.user == nil {
		return nil, fmt.Errorf("not authenticated")
	}

	// Unselect previous mailbox if any
	if s.sessionTracker != nil {
		s.sessionTracker.Close()
		s.sessionTracker = nil
	}

	mb, err := s.db.GetMailbox(s.user.ID, mailbox)
	if err != nil {
		return nil, err
	}
	if mb == nil {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "mailbox does not exist",
		}
	}

	s.selectedMailbox = mb

	msgCount, err := s.db.MailboxMessageCount(mb.ID)
	if err != nil {
		return nil, err
	}

	// Get or create a tracker for this mailbox
	tracker := s.server.GetTracker(mb.ID, uint32(msgCount))
	s.sessionTracker = tracker.NewSession()

	flags := []imap.Flag{
		imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged,
		imap.FlagDeleted, imap.FlagDraft,
	}

	return &imap.SelectData{
		Flags:          flags,
		PermanentFlags: append(flags, imap.FlagWildcard),
		NumMessages:    uint32(msgCount),
		UIDValidity:    uint32(mb.UIDValidity),
		UIDNext:        imap.UID(mb.UIDNext),
	}, nil
}

func (s *Session) Create(mailbox string, options *imap.CreateOptions) error {
	if s.user == nil {
		return fmt.Errorf("not authenticated")
	}

	mb := &storage.Mailbox{
		UserID:      s.user.ID,
		Name:        mailbox,
		UIDValidity: int(time.Now().Unix() & 0x7FFFFFFF),
		UIDNext:     1,
		Subscribed:  true,
	}
	return s.db.CreateMailbox(mb)
}

func (s *Session) Delete(mailbox string) error {
	if s.user == nil {
		return fmt.Errorf("not authenticated")
	}

	// Prevent deleting INBOX
	if strings.EqualFold(mailbox, "INBOX") {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "cannot delete INBOX",
		}
	}

	mb, err := s.db.GetMailbox(s.user.ID, mailbox)
	if err != nil {
		return err
	}
	if mb == nil {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "mailbox does not exist",
		}
	}
	return s.db.DeleteMailbox(mb.ID)
}

func (s *Session) Rename(mailbox, newName string, options *imap.RenameOptions) error {
	if s.user == nil {
		return fmt.Errorf("not authenticated")
	}
	if strings.EqualFold(mailbox, "INBOX") {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "cannot rename INBOX",
		}
	}

	mb, err := s.db.GetMailbox(s.user.ID, mailbox)
	if err != nil {
		return err
	}
	if mb == nil {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "mailbox does not exist",
		}
	}

	_, err = s.db.Exec("UPDATE mailboxes SET name = ? WHERE id = ?", newName, mb.ID)
	return err
}

func (s *Session) Subscribe(mailbox string) error {
	if s.user == nil {
		return fmt.Errorf("not authenticated")
	}
	mb, err := s.db.GetMailbox(s.user.ID, mailbox)
	if err != nil || mb == nil {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "mailbox not found"}
	}
	_, err = s.db.Exec("UPDATE mailboxes SET subscribed = 1 WHERE id = ?", mb.ID)
	return err
}

func (s *Session) Unsubscribe(mailbox string) error {
	if s.user == nil {
		return fmt.Errorf("not authenticated")
	}
	mb, err := s.db.GetMailbox(s.user.ID, mailbox)
	if err != nil || mb == nil {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "mailbox not found"}
	}
	_, err = s.db.Exec("UPDATE mailboxes SET subscribed = 0 WHERE id = ?", mb.ID)
	return err
}

func (s *Session) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	if s.user == nil {
		return fmt.Errorf("not authenticated")
	}

	mailboxes, err := s.db.ListMailboxes(s.user.ID)
	if err != nil {
		return err
	}

	for _, mb := range mailboxes {
		// Check if subscribed filter applies
		if options != nil && options.SelectSubscribed && !mb.Subscribed {
			continue
		}

		// Match against patterns
		matched := false
		for _, pattern := range patterns {
			if imapserver.MatchList(mb.Name, '/', ref, pattern) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		msgCount, _ := s.db.MailboxMessageCount(mb.ID)

		var attrs []imap.MailboxAttr
		if mb.SpecialUse != "" {
			attrs = append(attrs, imap.MailboxAttr(mb.SpecialUse))
		}

		listData := &imap.ListData{
			Mailbox: mb.Name,
			Delim:   '/',
			Attrs:   attrs,
		}

		if options != nil && options.ReturnStatus != nil {
			listData.Status = &imap.StatusData{
				Mailbox:     mb.Name,
				NumMessages: ptrUint32(uint32(msgCount)),
				UIDValidity: uint32(mb.UIDValidity),
				UIDNext:     imap.UID(mb.UIDNext),
			}
		}

		if err := w.WriteList(listData); err != nil {
			return err
		}
	}

	return nil
}

func (s *Session) Status(mailbox string, options *imap.StatusOptions) (*imap.StatusData, error) {
	if s.user == nil {
		return nil, fmt.Errorf("not authenticated")
	}

	mb, err := s.db.GetMailbox(s.user.ID, mailbox)
	if err != nil {
		return nil, err
	}
	if mb == nil {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "mailbox does not exist",
		}
	}

	msgCount, _ := s.db.MailboxMessageCount(mb.ID)

	data := &imap.StatusData{
		Mailbox:     mb.Name,
		UIDValidity: uint32(mb.UIDValidity),
		UIDNext:     imap.UID(mb.UIDNext),
	}

	if options.NumMessages {
		data.NumMessages = ptrUint32(uint32(msgCount))
	}
	if options.UIDValidity {
		// already set above
	}
	if options.UIDNext {
		// already set above
	}

	return data, nil
}

func (s *Session) Append(mailbox string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	if s.user == nil {
		return nil, fmt.Errorf("not authenticated")
	}

	mb, err := s.db.GetMailbox(s.user.ID, mailbox)
	if err != nil {
		return nil, err
	}
	if mb == nil {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeTryCreate,
			Text: "mailbox does not exist",
		}
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading message: %w", err)
	}

	internalDate := time.Now()
	if options != nil && !options.Time.IsZero() {
		internalDate = options.Time
	}

	flags := ""
	if options != nil && len(options.Flags) > 0 {
		flagStrs := make([]string, len(options.Flags))
		for i, f := range options.Flags {
			flagStrs[i] = string(f)
		}
		flags = strings.Join(flagStrs, " ")
	}

	msg := &storage.Message{
		MailboxID:    mb.ID,
		BodyEnc:      data, // Phase 1: plaintext. Phase 3: encrypted.
		Size:         len(data),
		Flags:        flags,
		InternalDate: internalDate,
	}

	if err := s.db.StoreMessage(msg); err != nil {
		return nil, err
	}

	// Notify other sessions
	newCount, _ := s.db.MailboxMessageCount(mb.ID)
	s.server.NotifyNewMessage(mb.ID, uint32(newCount))

	return &imap.AppendData{
		UIDValidity: uint32(mb.UIDValidity),
		UID:         imap.UID(msg.UID),
	}, nil
}

func (s *Session) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	if s.sessionTracker != nil {
		return s.sessionTracker.Poll(w, allowExpunge)
	}
	return nil
}

func (s *Session) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	if s.sessionTracker != nil {
		return s.sessionTracker.Idle(w, stop)
	}
	<-stop
	return nil
}

// --- Selected State ---

func (s *Session) Unselect() error {
	if s.sessionTracker != nil {
		s.sessionTracker.Close()
		s.sessionTracker = nil
	}
	s.selectedMailbox = nil
	return nil
}

func (s *Session) Namespace() (*imap.NamespaceData, error) {
	return &imap.NamespaceData{
		Personal: []imap.NamespaceDescriptor{
			{Prefix: "", Delim: '/'},
		},
	}, nil
}

func ptrUint32(v uint32) *uint32 {
	return &v
}
