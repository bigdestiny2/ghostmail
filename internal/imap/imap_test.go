package imap

import (
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/ghostmail/ghostmail/internal/config"
	"github.com/ghostmail/ghostmail/internal/crypto"
	"github.com/ghostmail/ghostmail/internal/storage"
	"github.com/ghostmail/ghostmail/internal/vault"
)

func testSetup(t *testing.T) (*Server, *storage.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	cfg := config.Defaults()
	cfg.Server.DataDir = dir
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	cryptoSvc := crypto.NewService(2, 19456, 1) // Minimum valid params for testing
	vaultStore := vault.NewStore(db, cryptoSvc, logger, 30*time.Minute)
	srv := NewServer(cfg, db, logger, nil, cryptoSvc, vaultStore)

	if err := db.CreateDomain(&storage.Domain{Name: "test.com", IsPrimary: true}); err != nil {
		t.Fatal(err)
	}

	// Create user with full crypto keys
	keys, err := cryptoSvc.RegisterUser([]byte("secret123"))
	if err != nil {
		t.Fatal("register user keys:", err)
	}
	if err := db.CreateUser(&storage.User{
		Username:          "alice",
		Domain:            "test.com",
		PasswordHash:      hex.EncodeToString(keys.AuthHash),
		PublicKey:          keys.PublicKey,
		WrappedPrivateKey: keys.WrappedPrivateKey,
		KeyNonce:          keys.KeyNonce,
		KeyParams:         keys.KeyParams,
		QuotaBytes:        104857600,
	}); err != nil {
		t.Fatal(err)
	}

	return srv, db
}

func testSession(t *testing.T, srv *Server) *Session {
	t.Helper()
	s := srv.newSession(nil)
	if err := s.Login("alice@test.com", "secret123"); err != nil {
		t.Fatal("login failed:", err)
	}
	return s
}

func storeTestMessage(t *testing.T, db *storage.DB, mailboxID int64, body string) *storage.Message {
	t.Helper()
	msg := &storage.Message{
		MailboxID:    mailboxID,
		BodyEnc:      []byte(body),
		Size:         len(body),
		InternalDate: time.Now(),
	}
	if err := db.StoreMessage(msg); err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestLogin(t *testing.T) {
	srv, _ := testSetup(t)

	s := srv.newSession(nil)
	defer s.Close()

	if err := s.Login("alice@test.com", "secret123"); err != nil {
		t.Fatal("expected login to succeed:", err)
	}

	s2 := srv.newSession(nil)
	defer s2.Close()
	if err := s2.Login("alice@test.com", "wrongpassword"); err == nil {
		t.Fatal("expected login to fail with wrong password")
	}

	s3 := srv.newSession(nil)
	defer s3.Close()
	if err := s3.Login("alice", "secret123"); err == nil {
		t.Fatal("expected login to fail without domain")
	}
}

func TestSelectAndList(t *testing.T) {
	srv, _ := testSetup(t)
	s := testSession(t, srv)
	defer s.Close()

	data, err := s.Select("INBOX", nil)
	if err != nil {
		t.Fatal("select INBOX:", err)
	}
	if data.UIDValidity == 0 {
		t.Error("expected non-zero UIDValidity")
	}
	if data.NumMessages != 0 {
		t.Errorf("expected 0 messages, got %d", data.NumMessages)
	}

	_, err = s.Select("NonExistent", nil)
	if err == nil {
		t.Fatal("expected error selecting non-existent mailbox")
	}
}

func TestCreateDeleteMailbox(t *testing.T) {
	srv, _ := testSetup(t)
	s := testSession(t, srv)
	defer s.Close()

	if err := s.Create("Archive", nil); err != nil {
		t.Fatal("create mailbox:", err)
	}

	data, err := s.Select("Archive", nil)
	if err != nil {
		t.Fatal("select Archive:", err)
	}
	if data.NumMessages != 0 {
		t.Error("new mailbox should have 0 messages")
	}

	if err := s.Unselect(); err != nil {
		t.Fatal("unselect:", err)
	}

	if err := s.Delete("Archive"); err != nil {
		t.Fatal("delete Archive:", err)
	}

	if err := s.Delete("INBOX"); err == nil {
		t.Fatal("should not be able to delete INBOX")
	}
}

func TestAppend(t *testing.T) {
	srv, db := testSetup(t)
	s := testSession(t, srv)
	defer s.Close()

	msgBody := "From: sender@example.com\r\nTo: alice@test.com\r\nSubject: Test\r\n\r\nHello World"
	appendData, err := s.Append("INBOX", newLiteralReader([]byte(msgBody)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagSeen},
	})
	if err != nil {
		t.Fatal("append:", err)
	}
	if appendData.UID == 0 {
		t.Error("expected non-zero UID")
	}

	// Verify via storage layer
	user, _ := db.GetUser("alice", "test.com")
	inbox, _ := db.GetMailbox(user.ID, "INBOX")
	msgs, _ := db.ListMessages(inbox.ID)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if !storage.HasFlag(msgs[0].Flags, "\\Seen") {
		t.Error("expected \\Seen flag on appended message")
	}
}

func TestStoreAndExpunge(t *testing.T) {
	srv, db := testSetup(t)
	s := testSession(t, srv)
	defer s.Close()

	user, _ := db.GetUser("alice", "test.com")
	inbox, _ := db.GetMailbox(user.ID, "INBOX")
	storeTestMessage(t, db, inbox.ID, "From: a@b.com\r\n\r\nmsg1")
	storeTestMessage(t, db, inbox.ID, "From: a@b.com\r\n\r\nmsg2")
	storeTestMessage(t, db, inbox.ID, "From: a@b.com\r\n\r\nmsg3")

	s.Select("INBOX", nil)

	// Use applyStoreFlags directly to verify flag logic
	result := applyStoreFlags("", &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen, imap.FlagFlagged},
	})
	if result != "\\Seen \\Flagged" {
		t.Errorf("expected '\\Seen \\Flagged', got %q", result)
	}

	// Test flag set operation
	result2 := applyStoreFlags("\\Seen \\Flagged", &imap.StoreFlags{
		Op:    imap.StoreFlagsSet,
		Flags: []imap.Flag{imap.FlagDraft},
	})
	if result2 != "\\Draft" {
		t.Errorf("expected '\\Draft', got %q", result2)
	}

	// Test flag delete operation
	result3 := applyStoreFlags("\\Seen \\Flagged", &imap.StoreFlags{
		Op:    imap.StoreFlagsDel,
		Flags: []imap.Flag{imap.FlagSeen},
	})
	if result3 != "\\Flagged" {
		t.Errorf("expected '\\Flagged', got %q", result3)
	}

	// Verify we can mark and delete through DB
	db.UpdateFlags(1, "\\Deleted")
	msg, _ := db.GetMessage(inbox.ID, 1)
	if !storage.HasFlag(msg.Flags, "\\Deleted") {
		t.Error("expected \\Deleted flag")
	}
}

func TestCopyViaStorage(t *testing.T) {
	srv, db := testSetup(t)
	s := testSession(t, srv)
	defer s.Close()

	user, _ := db.GetUser("alice", "test.com")
	inbox, _ := db.GetMailbox(user.ID, "INBOX")
	storeTestMessage(t, db, inbox.ID, "From: a@b.com\r\n\r\ncopy test")

	s.Select("INBOX", nil)

	seqSet := imap.SeqSet{}
	seqSet.AddNum(1)
	copyData, err := s.Copy(seqSet, "Sent")
	if err != nil {
		t.Fatal("copy:", err)
	}
	if copyData.UIDValidity == 0 {
		t.Error("expected non-zero UIDValidity")
	}

	inboxCount, _ := db.MailboxMessageCount(inbox.ID)
	sent, _ := db.GetMailbox(user.ID, "Sent")
	sentCount, _ := db.MailboxMessageCount(sent.ID)

	if inboxCount != 1 {
		t.Errorf("inbox should have 1 message, got %d", inboxCount)
	}
	if sentCount != 1 {
		t.Errorf("sent should have 1 message, got %d", sentCount)
	}
}

func TestSearch(t *testing.T) {
	srv, db := testSetup(t)
	s := testSession(t, srv)
	defer s.Close()

	user, _ := db.GetUser("alice", "test.com")
	inbox, _ := db.GetMailbox(user.ID, "INBOX")
	storeTestMessage(t, db, inbox.ID, "From: a@b.com\r\nSubject: Hello\r\n\r\nworld")
	storeTestMessage(t, db, inbox.ID, "From: c@d.com\r\nSubject: Goodbye\r\n\r\nuniverse")
	storeTestMessage(t, db, inbox.ID, "From: a@b.com\r\nSubject: Hello Again\r\n\r\nworld again")

	s.Select("INBOX", nil)

	// Search by body text
	criteria := &imap.SearchCriteria{
		Body: []string{"world"},
	}
	result, err := s.Search(imapserver.NumKindUID, criteria, nil)
	if err != nil {
		t.Fatal("search:", err)
	}
	uids := result.AllUIDs()
	if len(uids) != 2 {
		t.Errorf("expected 2 search results for 'world', got %d", len(uids))
	}

	// Search by flag (none flagged)
	criteria2 := &imap.SearchCriteria{
		Flag: []imap.Flag{imap.FlagSeen},
	}
	result2, err := s.Search(imapserver.NumKindUID, criteria2, nil)
	if err != nil {
		t.Fatal("search by flag:", err)
	}
	uids2 := result2.AllUIDs()
	if len(uids2) != 0 {
		t.Errorf("expected 0 flagged results, got %d", len(uids2))
	}

	// Search by size
	criteria3 := &imap.SearchCriteria{
		Larger: 100,
	}
	result3, err := s.Search(imapserver.NumKindUID, criteria3, nil)
	if err != nil {
		t.Fatal("search by size:", err)
	}
	uids3 := result3.AllUIDs()
	if len(uids3) != 0 {
		t.Errorf("expected 0 large messages, got %d", len(uids3))
	}

	// NOT search
	criteria4 := &imap.SearchCriteria{
		Not: []imap.SearchCriteria{
			{Body: []string{"universe"}},
		},
	}
	result4, err := s.Search(imapserver.NumKindUID, criteria4, nil)
	if err != nil {
		t.Fatal("NOT search:", err)
	}
	uids4 := result4.AllUIDs()
	if len(uids4) != 2 {
		t.Errorf("expected 2 results for NOT universe, got %d", len(uids4))
	}
}

func TestResolveNumSet(t *testing.T) {
	msgs := []*storage.Message{
		{UID: 1}, {UID: 3}, {UID: 5},
	}

	// Test SeqSet
	seqSet := imap.SeqSet{}
	seqSet.AddNum(1)
	seqSet.AddNum(3)
	result := resolveNumSet(msgs, seqSet)
	if len(result) != 2 {
		t.Errorf("seqSet: expected 2 matches, got %d", len(result))
	}

	// Test UIDSet
	uidSet := imap.UIDSet{}
	uidSet.AddNum(3)
	uidSet.AddNum(5)
	result2 := resolveNumSet(msgs, uidSet)
	if len(result2) != 2 {
		t.Errorf("uidSet: expected 2 matches, got %d", len(result2))
	}
}

func TestParseFlags(t *testing.T) {
	flags := parseFlags("\\Seen \\Flagged")
	if len(flags) != 2 {
		t.Errorf("expected 2 flags, got %d", len(flags))
	}
	if flags[0] != imap.FlagSeen {
		t.Errorf("expected \\Seen, got %s", flags[0])
	}

	empty := parseFlags("")
	if len(empty) != 0 {
		t.Errorf("expected 0 flags for empty string, got %d", len(empty))
	}
}

func TestNamespace(t *testing.T) {
	srv, _ := testSetup(t)
	s := testSession(t, srv)
	defer s.Close()

	ns, err := s.Namespace()
	if err != nil {
		t.Fatal(err)
	}
	if len(ns.Personal) != 1 {
		t.Errorf("expected 1 personal namespace, got %d", len(ns.Personal))
	}
	if ns.Personal[0].Delim != '/' {
		t.Errorf("expected '/' delimiter, got %c", ns.Personal[0].Delim)
	}
}

func TestHeaderParsing(t *testing.T) {
	msg := []byte("From: alice@test.com\r\nSubject: Hello World\r\nDate: Mon, 01 Jan 2024 12:00:00 +0000\r\n\r\nBody here")

	h := parseMessageHeader(msg)
	if h.Get("From") != "alice@test.com" {
		t.Errorf("From = %q", h.Get("From"))
	}
	if h.Get("Subject") != "Hello World" {
		t.Errorf("Subject = %q", h.Get("Subject"))
	}

	if !headerContainsValue(msg, "Subject", "hello") {
		t.Error("expected case-insensitive header match")
	}

	date := extractDate(msg)
	if date.IsZero() {
		t.Error("expected non-zero date")
	}
}

// literalReader implements imap.LiteralReader for testing.
type literalReader struct {
	data []byte
	pos  int
}

func newLiteralReader(data []byte) *literalReader {
	return &literalReader{data: data}
}

func (r *literalReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	if r.pos >= len(r.data) {
		return n, io.EOF
	}
	return n, nil
}

func (r *literalReader) Size() int64 {
	return int64(len(r.data))
}
