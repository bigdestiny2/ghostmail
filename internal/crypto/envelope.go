package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

// Envelope encryption: each message gets a random AES-256-GCM key,
// and that key is wrapped (encrypted) with the recipient's X25519 public key.
//
// Encrypt flow:
//   1. Generate random 32-byte messageKey
//   2. AES-256-GCM encrypt plaintext with messageKey -> ciphertext + nonce
//   3. Wrap messageKey with recipient's X25519 public key using ECDH + AES-256-GCM
//   4. Store: wrappedKey + keyNonce + ciphertext + bodyNonce
//
// Decrypt flow:
//   1. Unwrap messageKey using recipient's X25519 private key
//   2. AES-256-GCM decrypt ciphertext with messageKey

// GenerateX25519Keypair generates a new X25519 key pair.
func GenerateX25519Keypair() (publicKey, privateKey []byte, err error) {
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating X25519 key: %w", err)
	}
	return privKey.PublicKey().Bytes(), privKey.Bytes(), nil
}

// WrapPrivateKey encrypts an X25519 private key with the user's encryption sub-key.
// Uses AES-256-GCM for the wrapping.
func WrapPrivateKey(privateKey []byte, encryptionKey []byte) (wrapped []byte, nonce []byte, err error) {
	return EncryptAESGCM(privateKey, encryptionKey)
}

// UnwrapPrivateKey decrypts an X25519 private key with the user's encryption sub-key.
func UnwrapPrivateKey(wrapped []byte, nonce []byte, encryptionKey []byte) ([]byte, error) {
	return DecryptAESGCM(wrapped, nonce, encryptionKey)
}

// EncryptMessage performs envelope encryption for a message.
// Returns the encrypted body, its nonce, the wrapped message key, and the key nonce.
func EncryptMessage(plaintext []byte, recipientPublicKey []byte) (
	bodyEnc, bodyNonce, wrappedKey, keyNonce []byte, err error,
) {
	// 1. Generate random per-message key
	messageKey, err := GenerateRandom(32)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generating message key: %w", err)
	}
	defer Wipe(messageKey)

	// 2. Encrypt the message body with AES-256-GCM using the message key
	bodyEnc, bodyNonce, err = EncryptAESGCM(plaintext, messageKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("encrypting body: %w", err)
	}

	// 3. Wrap the message key with the recipient's public key
	wrappedKey, keyNonce, err = WrapMessageKey(messageKey, recipientPublicKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("wrapping message key: %w", err)
	}

	return bodyEnc, bodyNonce, wrappedKey, keyNonce, nil
}

// DecryptMessage performs envelope decryption.
func DecryptMessage(bodyEnc, bodyNonce, wrappedKey, keyNonce, recipientPrivateKey []byte) ([]byte, error) {
	// 1. Unwrap the message key
	messageKey, err := UnwrapMessageKey(wrappedKey, keyNonce, recipientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("unwrapping message key: %w", err)
	}
	defer Wipe(messageKey)

	// 2. Decrypt the body
	plaintext, err := DecryptAESGCM(bodyEnc, bodyNonce, messageKey)
	if err != nil {
		return nil, fmt.Errorf("decrypting body: %w", err)
	}

	return plaintext, nil
}

// WrapMessageKey encrypts a message key using the recipient's X25519 public key.
// Uses ephemeral ECDH + HKDF + AES-256-GCM.
func WrapMessageKey(messageKey []byte, recipientPublicKey []byte) (wrapped []byte, nonce []byte, err error) {
	curve := ecdh.X25519()

	// Parse the recipient's public key
	recipPub, err := curve.NewPublicKey(recipientPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing recipient public key: %w", err)
	}

	// Generate an ephemeral keypair
	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating ephemeral key: %w", err)
	}

	// ECDH: ephemeral private + recipient public -> shared secret
	sharedSecret, err := ephPriv.ECDH(recipPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH: %w", err)
	}

	// Derive a wrapping key from the shared secret via HKDF
	var wrappingKey [32]byte
	if err := deriveSubKey(sharedSecret, "ghostmail-keywrap", &wrappingKey); err != nil {
		return nil, nil, fmt.Errorf("deriving wrapping key: %w", err)
	}
	defer WipeKey(&wrappingKey)

	// Encrypt the message key with AES-256-GCM
	encrypted, gcmNonce, err := EncryptAESGCM(messageKey, wrappingKey[:])
	if err != nil {
		return nil, nil, err
	}

	// Prepend the ephemeral public key to the wrapped output
	// Format: [32-byte ephemeral pubkey] [encrypted message key]
	ephPub := ephPriv.PublicKey().Bytes()
	wrapped = make([]byte, len(ephPub)+len(encrypted))
	copy(wrapped[:len(ephPub)], ephPub)
	copy(wrapped[len(ephPub):], encrypted)

	return wrapped, gcmNonce, nil
}

// UnwrapMessageKey decrypts a message key using the recipient's X25519 private key.
func UnwrapMessageKey(wrapped []byte, nonce []byte, recipientPrivateKey []byte) ([]byte, error) {
	curve := ecdh.X25519()

	if len(wrapped) < 32 {
		return nil, fmt.Errorf("wrapped key too short")
	}

	// Extract the ephemeral public key
	ephPubBytes := wrapped[:32]
	encryptedKey := wrapped[32:]

	ephPub, err := curve.NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing ephemeral public key: %w", err)
	}

	// Parse the recipient's private key
	recipPriv, err := curve.NewPrivateKey(recipientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing recipient private key: %w", err)
	}

	// ECDH: recipient private + ephemeral public -> shared secret
	sharedSecret, err := recipPriv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	// Derive the same wrapping key
	var wrappingKey [32]byte
	if err := deriveSubKey(sharedSecret, "ghostmail-keywrap", &wrappingKey); err != nil {
		return nil, fmt.Errorf("deriving wrapping key: %w", err)
	}
	defer WipeKey(&wrappingKey)

	// Decrypt the message key
	return DecryptAESGCM(encryptedKey, nonce, wrappingKey[:])
}

// --- AES-256-GCM primitives ---

// EncryptAESGCM encrypts plaintext with AES-256-GCM.
// Returns ciphertext (with appended auth tag) and the nonce.
func EncryptAESGCM(plaintext, key []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// DecryptAESGCM decrypts AES-256-GCM ciphertext.
func DecryptAESGCM(ciphertext, nonce, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (invalid key or tampered data): %w", err)
	}

	return plaintext, nil
}

// EncryptFields encrypts multiple fields (e.g., headers and body separately)
// with the same message key. Each field gets its own nonce.
type EncryptedField struct {
	Data  []byte
	Nonce []byte
}

// EncryptMultiple encrypts multiple plaintexts with the same key.
func EncryptMultiple(plaintexts [][]byte, key []byte) ([]EncryptedField, error) {
	fields := make([]EncryptedField, len(plaintexts))
	for i, pt := range plaintexts {
		ct, nonce, err := EncryptAESGCM(pt, key)
		if err != nil {
			return nil, fmt.Errorf("encrypting field %d: %w", i, err)
		}
		fields[i] = EncryptedField{Data: ct, Nonce: nonce}
	}
	return fields, nil
}
