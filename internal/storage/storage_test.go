package storage

import (
	"testing"
	"time"
)

func testDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOpenAndMigrate(t *testing.T) {
	db := testDB(t)
	var version int
	err := db.QueryRow("SELECT version FROM schema_version").Scan(&version)
	if err != nil {
		t.Fatal(err)
	}
	if version != currentSchemaVersion {
		t.Errorf("schema version = %d, want %d", version, currentSchemaVersion)
	}
}

func TestUserCRUD(t *testing.T) {
	db := testDB(t)

	// Create domain first
	err := db.CreateDomain(&Domain{Name: "example.com", IsPrimary: true})
	if err != nil {
		t.Fatal(err)
	}

	// Create user
	u := &User{
		Username:     "alice",
		Domain:       "example.com",
		PasswordHash: "hash123",
		QuotaBytes:   1048576,
	}
	if err := db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if u.ID == 0 {
		t.Error("expected user ID to be set")
	}

	// Verify default mailboxes were created
	mailboxes, err := db.ListMailboxes(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(mailboxes) != 5 {
		t.Errorf("expected 5 default mailboxes, got %d", len(mailboxes))
	}

	// Get user
	got, err := db.GetUser("alice", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected user, got nil")
	}
	if got.Username != "alice" {
		t.Errorf("username = %q, want alice", got.Username)
	}

	// List users
	users, err := db.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 {
		t.Errorf("expected 1 user, got %d", len(users))
	}

	// Delete user
	if err := db.DeleteUser(u.ID); err != nil {
		t.Fatal(err)
	}
	got, err = db.GetUser("alice", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Error("expected nil after deletion")
	}
}

func TestMessageStorage(t *testing.T) {
	db := testDB(t)

	err := db.CreateDomain(&Domain{Name: "test.com", IsPrimary: true})
	if err != nil {
		t.Fatal(err)
	}

	u := &User{Username: "bob", Domain: "test.com", PasswordHash: "h"}
	if err := db.CreateUser(u); err != nil {
		t.Fatal(err)
	}

	inbox, err := db.GetMailbox(u.ID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if inbox == nil {
		t.Fatal("INBOX not found")
	}

	// Store message
	msg := &Message{
		MailboxID:    inbox.ID,
		BodyEnc:      []byte("encrypted body data"),
		Size:         100,
		InternalDate: time.Now(),
	}
	if err := db.StoreMessage(msg); err != nil {
		t.Fatal(err)
	}
	if msg.UID != 1 {
		t.Errorf("expected UID 1, got %d", msg.UID)
	}

	// Store a second message
	msg2 := &Message{
		MailboxID:    inbox.ID,
		BodyEnc:      []byte("second message"),
		Size:         50,
		InternalDate: time.Now(),
	}
	if err := db.StoreMessage(msg2); err != nil {
		t.Fatal(err)
	}
	if msg2.UID != 2 {
		t.Errorf("expected UID 2, got %d", msg2.UID)
	}

	// List messages
	msgs, err := db.ListMessages(inbox.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Errorf("expected 2 messages, got %d", len(msgs))
	}

	// Get specific message
	got, err := db.GetMessage(inbox.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected message, got nil")
	}
	if string(got.BodyEnc) != "encrypted body data" {
		t.Errorf("body mismatch: %s", got.BodyEnc)
	}

	// Update flags
	if err := db.UpdateFlags(msg.ID, "\\Seen \\Flagged"); err != nil {
		t.Fatal(err)
	}
	got, _ = db.GetMessage(inbox.ID, 1)
	if !HasFlag(got.Flags, "\\Seen") {
		t.Error("expected \\Seen flag")
	}
}

func TestMessageExpiry(t *testing.T) {
	db := testDB(t)

	err := db.CreateDomain(&Domain{Name: "test.com"})
	if err != nil {
		t.Fatal(err)
	}

	u := &User{Username: "carol", Domain: "test.com", PasswordHash: "h"}
	if err := db.CreateUser(u); err != nil {
		t.Fatal(err)
	}

	inbox, _ := db.GetMailbox(u.ID, "INBOX")
	past := time.Now().Add(-1 * time.Hour)
	future := time.Now().Add(1 * time.Hour)

	// Store expired message
	if err := db.StoreMessage(&Message{
		MailboxID: inbox.ID, BodyEnc: []byte("expired"), Size: 10,
		InternalDate: time.Now(), ExpiresAt: &past,
	}); err != nil {
		t.Fatal(err)
	}
	// Store non-expired message
	if err := db.StoreMessage(&Message{
		MailboxID: inbox.ID, BodyEnc: []byte("valid"), Size: 10,
		InternalDate: time.Now(), ExpiresAt: &future,
	}); err != nil {
		t.Fatal(err)
	}
	// Store message without expiry
	if err := db.StoreMessage(&Message{
		MailboxID: inbox.ID, BodyEnc: []byte("permanent"), Size: 10,
		InternalDate: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	count, err := db.DeleteExpiredMessages(time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected 1 expired message deleted, got %d", count)
	}

	msgs, _ := db.ListMessages(inbox.ID)
	if len(msgs) != 2 {
		t.Errorf("expected 2 remaining messages, got %d", len(msgs))
	}
}

func TestAliases(t *testing.T) {
	db := testDB(t)

	err := db.CreateDomain(&Domain{Name: "test.com"})
	if err != nil {
		t.Fatal(err)
	}

	u := &User{Username: "dave", Domain: "test.com", PasswordHash: "h"}
	if err := db.CreateUser(u); err != nil {
		t.Fatal(err)
	}

	a := &Alias{
		UserID:      u.ID,
		Address:     "random123@test.com",
		Domain:      "test.com",
		Description: "signup alias",
		IsActive:    true,
	}
	if err := db.CreateAlias(a); err != nil {
		t.Fatal(err)
	}

	// Resolve
	got, err := db.ResolveAlias("random123@test.com")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected alias")
	}
	if got.UserID != u.ID {
		t.Errorf("expected user ID %d, got %d", u.ID, got.UserID)
	}

	// Increment count
	if err := db.IncrementAliasCount(a.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = db.ResolveAlias("random123@test.com")
	if got.MessageCount != 1 {
		t.Errorf("expected count 1, got %d", got.MessageCount)
	}

	// Deactivate
	if err := db.DeactivateAlias(a.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = db.ResolveAlias("random123@test.com")
	if got.IsActive {
		t.Error("expected alias to be inactive")
	}
}

func TestSendQueue(t *testing.T) {
	db := testDB(t)

	if err := db.EnqueueMessage("alice@test.com", "bob@ext.com", []byte("test email")); err != nil {
		t.Fatal(err)
	}

	size, _ := db.QueueSize()
	if size != 1 {
		t.Errorf("expected queue size 1, got %d", size)
	}

	items, err := db.DequeueMessages(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 queue item, got %d", len(items))
	}

	// Mark sent
	if err := db.MarkSent(items[0].ID); err != nil {
		t.Fatal(err)
	}
	size, _ = db.QueueSize()
	if size != 0 {
		t.Errorf("expected queue size 0, got %d", size)
	}
}

func TestFlags(t *testing.T) {
	if !HasFlag("\\Seen \\Flagged", "\\Seen") {
		t.Error("should have \\Seen")
	}
	if HasFlag("\\Seen", "\\Flagged") {
		t.Error("should not have \\Flagged")
	}

	flags := AddFlag("\\Seen", "\\Flagged")
	if flags != "\\Seen \\Flagged" {
		t.Errorf("AddFlag = %q", flags)
	}
	flags = AddFlag(flags, "\\Seen") // no duplicate
	if flags != "\\Seen \\Flagged" {
		t.Errorf("AddFlag duplicate = %q", flags)
	}

	flags = RemoveFlag("\\Seen \\Flagged \\Draft", "\\Flagged")
	if flags != "\\Seen \\Draft" {
		t.Errorf("RemoveFlag = %q", flags)
	}
}

func TestAuditLog(t *testing.T) {
	db := testDB(t)

	if err := db.LogAudit("admin", "user.create", "alice@test.com"); err != nil {
		t.Fatal(err)
	}
	if err := db.LogAudit("admin", "domain.add", "test.com"); err != nil {
		t.Fatal(err)
	}

	entries, err := db.ListAuditLog(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 audit entries, got %d", len(entries))
	}
	// Most recent first
	if entries[0].Action != "domain.add" {
		t.Errorf("expected most recent first, got %s", entries[0].Action)
	}
}
