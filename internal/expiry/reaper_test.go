package expiry

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/ghostmail/ghostmail/internal/config"
	"github.com/ghostmail/ghostmail/internal/storage"
)

func testSetup(t *testing.T) (*storage.DB, *Reaper) {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	cfg := config.Defaults()
	cfg.Expiry.TrashTTL = "24h"
	cfg.Expiry.SpamTTL = "12h"

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	r, err := NewReaper(cfg, db, logger)
	if err != nil {
		t.Fatal(err)
	}

	db.CreateDomain(&storage.Domain{Name: "test.com"})
	db.CreateUser(&storage.User{Username: "alice", Domain: "test.com", PasswordHash: "h", QuotaBytes: 1048576})

	return db, r
}

func TestSweepDeletesExpired(t *testing.T) {
	db, r := testSetup(t)

	user, _ := db.GetUser("alice", "test.com")
	inbox, _ := db.GetMailbox(user.ID, "INBOX")

	past := time.Now().Add(-1 * time.Hour)
	future := time.Now().Add(1 * time.Hour)

	// Store expired message
	db.StoreMessage(&storage.Message{
		MailboxID: inbox.ID, BodyEnc: []byte("expired"), Size: 7,
		InternalDate: time.Now(), ExpiresAt: &past,
	})
	// Store non-expired
	db.StoreMessage(&storage.Message{
		MailboxID: inbox.ID, BodyEnc: []byte("valid"), Size: 5,
		InternalDate: time.Now(), ExpiresAt: &future,
	})
	// Store permanent
	db.StoreMessage(&storage.Message{
		MailboxID: inbox.ID, BodyEnc: []byte("permanent"), Size: 9,
		InternalDate: time.Now(),
	})

	r.sweep()

	msgs, _ := db.ListMessages(inbox.ID)
	if len(msgs) != 2 {
		t.Errorf("expected 2 messages after sweep, got %d", len(msgs))
	}
}

func TestMailboxTTLTrash(t *testing.T) {
	db, r := testSetup(t)

	user, _ := db.GetUser("alice", "test.com")
	trash, _ := db.GetMailbox(user.ID, "Trash")

	// Store a message in Trash without expiry
	db.StoreMessage(&storage.Message{
		MailboxID: trash.ID, BodyEnc: []byte("trashed msg"), Size: 11,
		InternalDate: time.Now(),
	})

	// Apply TTLs
	r.applyMailboxTTLs()

	// Message should now have an expiry set
	msgs, _ := db.ListMessages(trash.ID)
	if len(msgs) != 1 {
		t.Fatal("expected 1 message in trash")
	}
	if msgs[0].ExpiresAt == nil {
		t.Error("message in Trash should have expiry set after TTL application")
	}
}

func TestMailboxTTLSpam(t *testing.T) {
	db, r := testSetup(t)

	user, _ := db.GetUser("alice", "test.com")
	spam, _ := db.GetMailbox(user.ID, "Spam")

	db.StoreMessage(&storage.Message{
		MailboxID: spam.ID, BodyEnc: []byte("spam msg"), Size: 8,
		InternalDate: time.Now(),
	})

	r.applyMailboxTTLs()

	msgs, _ := db.ListMessages(spam.ID)
	if len(msgs) != 1 {
		t.Fatal("expected 1 message in spam")
	}
	if msgs[0].ExpiresAt == nil {
		t.Error("message in Spam should have expiry set after TTL application")
	}
}

func TestMailboxTTLDoesNotOverwrite(t *testing.T) {
	db, r := testSetup(t)

	user, _ := db.GetUser("alice", "test.com")
	trash, _ := db.GetMailbox(user.ID, "Trash")

	// Store a message with an existing expiry
	existing := time.Now().Add(1 * time.Hour)
	db.StoreMessage(&storage.Message{
		MailboxID: trash.ID, BodyEnc: []byte("already set"), Size: 11,
		InternalDate: time.Now(), ExpiresAt: &existing,
	})

	r.applyMailboxTTLs()

	msgs, _ := db.ListMessages(trash.ID)
	if msgs[0].ExpiresAt == nil {
		t.Fatal("expiry should still be set")
	}
	// Expiry should not be overwritten (original was ~1h, TTL is 24h)
	diff := msgs[0].ExpiresAt.Sub(time.Now())
	if diff > 2*time.Hour {
		t.Error("existing expiry should not be overwritten by longer TTL")
	}
}
