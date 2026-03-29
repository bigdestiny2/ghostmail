package crypto

import (
	"bytes"
	"testing"
)

func TestAESGCMRoundTrip(t *testing.T) {
	key, _ := GenerateRandom(32)
	plaintext := []byte("Hello, encrypted world!")

	ciphertext, nonce, err := EncryptAESGCM(plaintext, key)
	if err != nil {
		t.Fatal("encrypt:", err)
	}
	if bytes.Equal(plaintext, ciphertext) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	decrypted, err := DecryptAESGCM(ciphertext, nonce, key)
	if err != nil {
		t.Fatal("decrypt:", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("decrypted mismatch: got %q", decrypted)
	}
}

func TestAESGCMWrongKey(t *testing.T) {
	key1, _ := GenerateRandom(32)
	key2, _ := GenerateRandom(32)
	plaintext := []byte("secret data")

	ct, nonce, _ := EncryptAESGCM(plaintext, key1)

	_, err := DecryptAESGCM(ct, nonce, key2)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong key")
	}
}

func TestAESGCMTampered(t *testing.T) {
	key, _ := GenerateRandom(32)
	ct, nonce, _ := EncryptAESGCM([]byte("data"), key)

	// Tamper with ciphertext
	ct[0] ^= 0xFF
	_, err := DecryptAESGCM(ct, nonce, key)
	if err == nil {
		t.Fatal("expected decryption to fail with tampered data")
	}
}

func TestX25519KeypairGeneration(t *testing.T) {
	pub, priv, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != 32 {
		t.Errorf("public key length = %d, want 32", len(pub))
	}
	if len(priv) != 32 {
		t.Errorf("private key length = %d, want 32", len(priv))
	}
}

func TestEnvelopeEncryptionRoundTrip(t *testing.T) {
	pub, priv, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("This is a secret email body that should be encrypted")

	bodyEnc, bodyNonce, wrappedKey, keyNonce, err := EncryptMessage(plaintext, pub)
	if err != nil {
		t.Fatal("encrypt:", err)
	}
	if bytes.Equal(plaintext, bodyEnc) {
		t.Fatal("body should be encrypted")
	}

	decrypted, err := DecryptMessage(bodyEnc, bodyNonce, wrappedKey, keyNonce, priv)
	if err != nil {
		t.Fatal("decrypt:", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("decrypted body does not match original")
	}
}

func TestEnvelopeEncryptionWrongKey(t *testing.T) {
	pub1, _, _ := GenerateX25519Keypair()
	_, priv2, _ := GenerateX25519Keypair()

	plaintext := []byte("secret")
	bodyEnc, bodyNonce, wrappedKey, keyNonce, _ := EncryptMessage(plaintext, pub1)

	// Try decrypting with a different private key
	_, err := DecryptMessage(bodyEnc, bodyNonce, wrappedKey, keyNonce, priv2)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong private key")
	}
}

func TestEnvelopeEncryptionLargeMessage(t *testing.T) {
	pub, priv, _ := GenerateX25519Keypair()

	// 1MB message
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	bodyEnc, bodyNonce, wrappedKey, keyNonce, err := EncryptMessage(plaintext, pub)
	if err != nil {
		t.Fatal("encrypt large:", err)
	}

	decrypted, err := DecryptMessage(bodyEnc, bodyNonce, wrappedKey, keyNonce, priv)
	if err != nil {
		t.Fatal("decrypt large:", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("large message round-trip failed")
	}
}

func TestWrapUnwrapPrivateKey(t *testing.T) {
	_, privKey, _ := GenerateX25519Keypair()
	encKey, _ := GenerateRandom(32)

	wrapped, nonce, err := WrapPrivateKey(privKey, encKey)
	if err != nil {
		t.Fatal("wrap:", err)
	}

	unwrapped, err := UnwrapPrivateKey(wrapped, nonce, encKey)
	if err != nil {
		t.Fatal("unwrap:", err)
	}
	if !bytes.Equal(privKey, unwrapped) {
		t.Fatal("unwrapped key does not match original")
	}
}

func TestKeyDerivation(t *testing.T) {
	password := []byte("correct-horse-battery-staple")
	params, err := DefaultKeyParams(1, 4096, 1) // Fast params for testing
	if err != nil {
		t.Fatal(err)
	}

	dk1, err := DeriveFromPassword(password, params)
	if err != nil {
		t.Fatal("derive:", err)
	}
	defer dk1.Release()

	// Derive again with same password - should get same keys
	dk2, err := DeriveFromPassword(password, params)
	if err != nil {
		t.Fatal("derive2:", err)
	}
	defer dk2.Release()

	if !bytes.Equal(dk1.MasterKey.Bytes(), dk2.MasterKey.Bytes()) {
		t.Error("same password+salt should produce same master key")
	}
	if !bytes.Equal(dk1.AuthKey.Bytes(), dk2.AuthKey.Bytes()) {
		t.Error("auth keys should match")
	}
	if !bytes.Equal(dk1.EncryptionKey.Bytes(), dk2.EncryptionKey.Bytes()) {
		t.Error("encryption keys should match")
	}
	if !bytes.Equal(dk1.SearchKey.Bytes(), dk2.SearchKey.Bytes()) {
		t.Error("search keys should match")
	}

	// Sub-keys should be different from each other
	if bytes.Equal(dk1.AuthKey.Bytes(), dk1.EncryptionKey.Bytes()) {
		t.Error("auth and encryption keys should differ")
	}
	if bytes.Equal(dk1.AuthKey.Bytes(), dk1.SearchKey.Bytes()) {
		t.Error("auth and search keys should differ")
	}

	// Different password should produce different keys
	dk3, _ := DeriveFromPassword([]byte("wrong-password"), params)
	defer dk3.Release()
	if bytes.Equal(dk1.MasterKey.Bytes(), dk3.MasterKey.Bytes()) {
		t.Error("different passwords should produce different keys")
	}
}

func TestPasswordHashAndVerify(t *testing.T) {
	password := []byte("test-password-123")
	params, _ := DefaultKeyParams(1, 4096, 1)

	hash, err := HashPassword(password, params)
	if err != nil {
		t.Fatal("hash:", err)
	}
	if len(hash) != 32 {
		t.Errorf("hash length = %d, want 32", len(hash))
	}

	// Verify correct password
	if !VerifyPassword(password, params, hash) {
		t.Error("correct password should verify")
	}

	// Verify wrong password
	if VerifyPassword([]byte("wrong"), params, hash) {
		t.Error("wrong password should not verify")
	}
}

func TestKeyParamsSerialization(t *testing.T) {
	params, _ := DefaultKeyParams(3, 65536, 4)

	json := MarshalKeyParams(params)
	parsed, err := UnmarshalKeyParams(json)
	if err != nil {
		t.Fatal("unmarshal:", err)
	}

	if parsed.Time != params.Time {
		t.Errorf("time: got %d, want %d", parsed.Time, params.Time)
	}
	if parsed.Memory != params.Memory {
		t.Errorf("memory: got %d, want %d", parsed.Memory, params.Memory)
	}
	if !bytes.Equal(parsed.Salt, params.Salt) {
		t.Error("salt mismatch")
	}
}

func TestSearchTokenGeneration(t *testing.T) {
	key, _ := GenerateRandom(32)

	tokens := GenerateSearchTokens(key, "Hello World", "alice@test.com", "bob@test.com", "This is a test message body")

	if len(tokens) == 0 {
		t.Fatal("expected search tokens")
	}

	// Each token hash should be 32 bytes (HMAC-SHA256)
	for _, tok := range tokens {
		if len(tok.TokenHash) != 32 {
			t.Errorf("token hash length = %d, want 32", len(tok.TokenHash))
		}
	}

	// Query for "hello" should match a subject token
	queryHash := ComputeSearchQuery(key, "hello")
	found := false
	for _, tok := range tokens {
		if tok.Field == FieldSubject && bytes.Equal(tok.TokenHash, queryHash) {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find 'hello' in subject tokens")
	}

	// Query for "world" should also match
	queryHash2 := ComputeSearchQuery(key, "world")
	found2 := false
	for _, tok := range tokens {
		if tok.Field == FieldSubject && bytes.Equal(tok.TokenHash, queryHash2) {
			found2 = true
			break
		}
	}
	if !found2 {
		t.Error("expected to find 'world' in subject tokens")
	}

	// Query with different key should not match
	otherKey, _ := GenerateRandom(32)
	otherHash := ComputeSearchQuery(otherKey, "hello")
	for _, tok := range tokens {
		if bytes.Equal(tok.TokenHash, otherHash) {
			t.Error("different key should produce different token hashes")
		}
	}
}

func TestSearchTokenDedup(t *testing.T) {
	key, _ := GenerateRandom(32)

	// Repeated words should be deduped
	tokens := GenerateSearchTokens(key, "hello hello hello", "", "", "")
	count := 0
	for _, tok := range tokens {
		if tok.Field == FieldSubject {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 deduped subject token, got %d", count)
	}
}

func TestSearchStopWords(t *testing.T) {
	key, _ := GenerateRandom(32)

	tokens := GenerateSearchTokens(key, "the quick brown fox", "", "", "")
	// "the" should be filtered as a stop word
	queryHash := ComputeSearchQuery(key, "the")
	for _, tok := range tokens {
		if bytes.Equal(tok.TokenHash, queryHash) {
			t.Error("stop word 'the' should be filtered")
		}
	}
	// "quick" should be present
	queryHash2 := ComputeSearchQuery(key, "quick")
	found := false
	for _, tok := range tokens {
		if bytes.Equal(tok.TokenHash, queryHash2) {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'quick' to be in tokens")
	}
}

func TestSafeMem(t *testing.T) {
	key := NewLockedKey()
	copy(key.Key[:], []byte("abcdefghijklmnopqrstuvwxyz123456"))

	if key.Key[0] != 'a' {
		t.Error("key should contain data before wipe")
	}

	key.Release()

	// After release, key should be zeroed
	for i, b := range key.Key {
		if b != 0 {
			t.Errorf("key byte %d = %d after wipe, expected 0", i, b)
			break
		}
	}
}

func TestLockedBuffer(t *testing.T) {
	buf := NewLockedBuffer(64)
	copy(buf.Bytes(), "sensitive data here")

	if buf.Size() != 64 {
		t.Errorf("buffer size = %d, want 64", buf.Size())
	}

	buf.Release()

	for i, b := range buf.Bytes() {
		if b != 0 {
			t.Errorf("buffer byte %d = %d after wipe, expected 0", i, b)
			break
		}
	}
}

func TestConstantTimeEqual(t *testing.T) {
	a := []byte("hello")
	b := []byte("hello")
	c := []byte("world")
	d := []byte("hel")

	if !ConstantTimeEqual(a, b) {
		t.Error("equal slices should match")
	}
	if ConstantTimeEqual(a, c) {
		t.Error("different slices should not match")
	}
	if ConstantTimeEqual(a, d) {
		t.Error("different length should not match")
	}
}

func TestEncryptMultiple(t *testing.T) {
	key, _ := GenerateRandom(32)
	plaintexts := [][]byte{
		[]byte("header data"),
		[]byte("body data"),
		[]byte("envelope data"),
	}

	fields, err := EncryptMultiple(plaintexts, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 3 {
		t.Fatalf("expected 3 fields, got %d", len(fields))
	}

	// Each field should have unique nonce
	if bytes.Equal(fields[0].Nonce, fields[1].Nonce) {
		t.Error("nonces should differ")
	}

	// Decrypt each field
	for i, f := range fields {
		decrypted, err := DecryptAESGCM(f.Data, f.Nonce, key)
		if err != nil {
			t.Fatalf("decrypt field %d: %v", i, err)
		}
		if !bytes.Equal(decrypted, plaintexts[i]) {
			t.Fatalf("field %d mismatch", i)
		}
	}
}

// TestFullEncryptionFlow simulates the complete user registration and
// message send/receive flow to verify all crypto layers work together.
func TestFullEncryptionFlow(t *testing.T) {
	// --- User Registration ---
	password := []byte("user-password-secure")
	params, _ := DefaultKeyParams(1, 4096, 1)

	// Derive keys from password
	dk, err := DeriveFromPassword(password, params)
	if err != nil {
		t.Fatal("derive keys:", err)
	}

	// Generate X25519 keypair
	pubKey, privKey, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal("generate keypair:", err)
	}

	// Wrap private key with encryption sub-key
	wrappedPriv, privNonce, err := WrapPrivateKey(privKey, dk.EncryptionKey.Bytes())
	if err != nil {
		t.Fatal("wrap private key:", err)
	}

	// Store auth hash for password verification
	authHash := make([]byte, 32)
	copy(authHash, dk.AuthKey.Bytes())

	// Store search key hash for indexing
	searchKey := make([]byte, 32)
	copy(searchKey, dk.SearchKey.Bytes())

	dk.Release() // Wipe derived keys from memory

	// --- Incoming Message (SMTP receive) ---
	messageBody := "From: sender@ext.com\r\nSubject: Secret Meeting\r\n\r\nMeet at the park at noon."

	// Server encrypts message for the user
	bodyEnc, bodyNonce, msgKeyWrapped, msgKeyNonce, err := EncryptMessage([]byte(messageBody), pubKey)
	if err != nil {
		t.Fatal("encrypt message:", err)
	}

	// Generate search tokens (server has indexing key)
	tokens := GenerateSearchTokens(searchKey, "Secret Meeting", "sender@ext.com", "", "Meet at the park at noon.")

	// --- IMAP Login (user reads mail) ---
	// Re-derive keys from password
	dk2, err := DeriveFromPassword(password, params)
	if err != nil {
		t.Fatal("re-derive:", err)
	}
	defer dk2.Release()

	// Verify password
	if !ConstantTimeEqual(dk2.AuthKey.Bytes(), authHash) {
		t.Fatal("password verification failed")
	}

	// Unwrap private key
	recoveredPriv, err := UnwrapPrivateKey(wrappedPriv, privNonce, dk2.EncryptionKey.Bytes())
	if err != nil {
		t.Fatal("unwrap private key:", err)
	}
	if !bytes.Equal(recoveredPriv, privKey) {
		t.Fatal("recovered private key does not match original")
	}

	// --- IMAP FETCH (decrypt message) ---
	decrypted, err := DecryptMessage(bodyEnc, bodyNonce, msgKeyWrapped, msgKeyNonce, recoveredPriv)
	if err != nil {
		t.Fatal("decrypt message:", err)
	}
	if string(decrypted) != messageBody {
		t.Fatalf("decrypted message mismatch: got %q", decrypted)
	}

	// --- IMAP SEARCH (blind index query) ---
	queryHash := ComputeSearchQuery(dk2.SearchKey.Bytes(), "secret")
	found := false
	for _, tok := range tokens {
		if tok.Field == FieldSubject && bytes.Equal(tok.TokenHash, queryHash) {
			found = true
			break
		}
	}
	if !found {
		t.Error("blind index search for 'secret' should match subject")
	}

	t.Log("Full encryption flow: registration -> encrypt -> login -> decrypt -> search: PASSED")
}
