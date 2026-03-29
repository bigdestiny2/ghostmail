package alias

import (
	"strings"
	"testing"
	"time"

	"github.com/ghostmail/ghostmail/internal/storage"
)

func testDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.CreateDomain(&storage.Domain{Name: "test.com", IsPrimary: true})
	db.CreateUser(&storage.User{Username: "alice", Domain: "test.com", PasswordHash: "h", QuotaBytes: 1048576})
	return db
}

func TestCreateAndResolve(t *testing.T) {
	db := testDB(t)
	gen := NewGenerator(db, 50)

	user, _ := db.GetUser("alice", "test.com")

	a, err := gen.Create(user.ID, "test.com", "newsletter signup", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(a.Address, "@test.com") {
		t.Errorf("alias should end with @test.com: %s", a.Address)
	}
	if len(strings.Split(a.Address, "@")[0]) != 12 {
		t.Errorf("alias local part should be 12 chars: %s", a.Address)
	}

	// Resolve the alias
	resolved, isAlias, err := gen.Resolve(a.Address)
	if err != nil {
		t.Fatal(err)
	}
	if !isAlias {
		t.Error("should be flagged as alias")
	}
	if resolved.ID != user.ID {
		t.Errorf("resolved to wrong user: %d vs %d", resolved.ID, user.ID)
	}
}

func TestResolveDirectUser(t *testing.T) {
	db := testDB(t)
	gen := NewGenerator(db, 50)

	resolved, isAlias, err := gen.Resolve("alice@test.com")
	if err != nil {
		t.Fatal(err)
	}
	if isAlias {
		t.Error("direct user should not be flagged as alias")
	}
	if resolved == nil || resolved.Username != "alice" {
		t.Error("should resolve to alice")
	}
}

func TestResolveNotFound(t *testing.T) {
	db := testDB(t)
	gen := NewGenerator(db, 50)

	resolved, _, err := gen.Resolve("nobody@test.com")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != nil {
		t.Error("should return nil for non-existent address")
	}
}

func TestAliasWithTTL(t *testing.T) {
	db := testDB(t)
	gen := NewGenerator(db, 50)
	user, _ := db.GetUser("alice", "test.com")

	// Create alias that expired 1 hour ago
	a, _ := gen.Create(user.ID, "test.com", "temp", 0, 0)
	past := time.Now().Add(-1 * time.Hour)
	db.Exec("UPDATE aliases SET expires_at = ? WHERE id = ?", past.Unix(), a.ID)

	_, _, err := gen.Resolve(a.Address)
	if err == nil {
		t.Error("expired alias should return error")
	}
}

func TestAliasMessageLimit(t *testing.T) {
	db := testDB(t)
	gen := NewGenerator(db, 50)
	user, _ := db.GetUser("alice", "test.com")

	a, _ := gen.Create(user.ID, "test.com", "limited", 0, 2)

	// First two resolves should work (incrementing count)
	_, _, err := gen.Resolve(a.Address)
	if err != nil {
		t.Fatal("resolve 1:", err)
	}
	_, _, err = gen.Resolve(a.Address)
	if err != nil {
		t.Fatal("resolve 2:", err)
	}

	// Third should fail (limit=2)
	_, _, err = gen.Resolve(a.Address)
	if err == nil {
		t.Error("should fail after message limit reached")
	}
}

func TestAliasLimit(t *testing.T) {
	db := testDB(t)
	gen := NewGenerator(db, 3) // Low limit for testing
	user, _ := db.GetUser("alice", "test.com")

	for i := 0; i < 3; i++ {
		_, err := gen.Create(user.ID, "test.com", "", 0, 0)
		if err != nil {
			t.Fatalf("create alias %d: %v", i, err)
		}
	}

	// Fourth should fail
	_, err := gen.Create(user.ID, "test.com", "", 0, 0)
	if err == nil {
		t.Error("should fail when alias limit reached")
	}
}

func TestCustomAlias(t *testing.T) {
	db := testDB(t)
	gen := NewGenerator(db, 50)
	user, _ := db.GetUser("alice", "test.com")

	a, err := gen.GenerateCustom(user.ID, "myalias", "test.com", "custom")
	if err != nil {
		t.Fatal(err)
	}
	if a.Address != "myalias@test.com" {
		t.Errorf("expected myalias@test.com, got %s", a.Address)
	}

	resolved, isAlias, err := gen.Resolve("myalias@test.com")
	if err != nil {
		t.Fatal(err)
	}
	if !isAlias {
		t.Error("should be alias")
	}
	if resolved.Username != "alice" {
		t.Error("should resolve to alice")
	}
}
