package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func TestGeneratePGPKey(t *testing.T) {
	pub, priv, err := GeneratePGPKey("Test User", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(pub, "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Error("public key should be armored PGP")
	}
	if !strings.Contains(priv, "BEGIN PGP PRIVATE KEY BLOCK") {
		t.Error("private key should be armored PGP")
	}
}

func TestImportPublicKey(t *testing.T) {
	pub, _, err := GeneratePGPKey("Alice", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}

	pgp := NewPGPService()
	info, err := pgp.ImportPublicKey(pub)
	if err != nil {
		t.Fatal("import:", err)
	}

	if info.Fingerprint == "" {
		t.Error("fingerprint should not be empty")
	}
	if info.KeyID == "" {
		t.Error("key ID should not be empty")
	}
	if !info.CanEncrypt {
		t.Error("key should be able to encrypt")
	}
	if len(info.PublicKeyBytes) == 0 {
		t.Error("public key bytes should not be empty")
	}
}

func TestImportRejectsPrivateKey(t *testing.T) {
	_, priv, _ := GeneratePGPKey("Test", "test@test.com")
	pgp := NewPGPService()
	_, err := pgp.ImportPublicKey(priv)
	if err == nil {
		t.Error("should reject private key import")
	}
}

func TestPGPEncryptForRecipient(t *testing.T) {
	pub, _, err := GeneratePGPKey("Bob", "bob@example.com")
	if err != nil {
		t.Fatal(err)
	}

	pgp := NewPGPService()
	info, err := pgp.ImportPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("Secret message for Bob")
	encrypted, err := pgp.EncryptForRecipient(plaintext, info.PublicKeyBytes)
	if err != nil {
		t.Fatal("encrypt:", err)
	}

	if !bytes.Contains(encrypted, []byte("BEGIN PGP MESSAGE")) {
		t.Error("encrypted output should be armored PGP message")
	}
	if bytes.Contains(encrypted, plaintext) {
		t.Error("plaintext should not appear in encrypted output")
	}
}

func TestPGPEncryptMIME(t *testing.T) {
	pub, _, err := GeneratePGPKey("Carol", "carol@example.com")
	if err != nil {
		t.Fatal(err)
	}

	pgp := NewPGPService()
	info, _ := pgp.ImportPublicKey(pub)

	message := []byte("From: alice@test.com\r\nTo: carol@example.com\r\nSubject: Secret\r\n\r\nThis is confidential.")

	encrypted, err := pgp.EncryptMIME(message, info.PublicKeyBytes)
	if err != nil {
		t.Fatal("encrypt MIME:", err)
	}

	// Should have PGP/MIME headers
	if !bytes.Contains(encrypted, []byte("multipart/encrypted")) {
		t.Error("should contain PGP/MIME content type")
	}
	if !bytes.Contains(encrypted, []byte("application/pgp-encrypted")) {
		t.Error("should contain PGP part")
	}
	// Original subject preserved in headers
	if !bytes.Contains(encrypted, []byte("Subject: Secret")) {
		t.Error("should preserve original headers")
	}
	// Body should be encrypted
	if bytes.Contains(encrypted, []byte("This is confidential")) {
		t.Error("plaintext body should not appear")
	}
}

func TestPGPKeyFingerprint(t *testing.T) {
	pub1, _, _ := GeneratePGPKey("User1", "u1@test.com")
	pub2, _, _ := GeneratePGPKey("User2", "u2@test.com")

	pgp := NewPGPService()
	info1, _ := pgp.ImportPublicKey(pub1)
	info2, _ := pgp.ImportPublicKey(pub2)

	if info1.Fingerprint == info2.Fingerprint {
		t.Error("different keys should have different fingerprints")
	}
}
