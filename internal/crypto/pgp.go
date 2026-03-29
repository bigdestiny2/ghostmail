package crypto

import (
	"bytes"
	"fmt"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// PGPService provides OpenPGP operations for external contact encryption.
type PGPService struct{}

// NewPGPService creates a new PGP service.
func NewPGPService() *PGPService {
	return &PGPService{}
}

// ImportPublicKey parses an armored PGP public key and returns the key
// along with extracted metadata (fingerprint, email, etc.).
func (p *PGPService) ImportPublicKey(armoredKey string) (*PGPKeyInfo, error) {
	key, err := crypto.NewKeyFromArmored(armoredKey)
	if err != nil {
		return nil, fmt.Errorf("parsing PGP key: %w", err)
	}

	if key.IsPrivate() {
		return nil, fmt.Errorf("expected public key, got private key")
	}

	now := time.Now().Unix()
	if !key.CanEncrypt(now) {
		return nil, fmt.Errorf("key cannot encrypt (expired or revoked)")
	}

	info := &PGPKeyInfo{
		Fingerprint: key.GetFingerprint(),
		KeyID:       key.GetHexKeyID(),
		CanEncrypt:  key.CanEncrypt(now),
	}

	// Get serialized public key bytes for storage
	pubBytes, err := key.GetPublicKey()
	if err != nil {
		return nil, fmt.Errorf("serializing public key: %w", err)
	}
	info.PublicKeyBytes = pubBytes

	return info, nil
}

// PGPKeyInfo holds metadata about an imported PGP key.
type PGPKeyInfo struct {
	Fingerprint    string
	KeyID          string
	CanEncrypt     bool
	PublicKeyBytes []byte // serialized binary public key
}

// EncryptForRecipient encrypts a message body using the recipient's PGP public key.
// Returns the ASCII-armored PGP message.
func (p *PGPService) EncryptForRecipient(plaintext []byte, recipientPublicKey []byte) ([]byte, error) {
	key, err := crypto.NewKey(recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("loading recipient key: %w", err)
	}

	pgp := crypto.PGP()
	encHandle, err := pgp.Encryption().Recipient(key).New()
	if err != nil {
		return nil, fmt.Errorf("creating encryption handle: %w", err)
	}

	pgpMsg, err := encHandle.Encrypt(plaintext)
	if err != nil {
		return nil, fmt.Errorf("PGP encryption: %w", err)
	}

	armored, err := pgpMsg.ArmorBytes()
	if err != nil {
		return nil, fmt.Errorf("armoring PGP message: %w", err)
	}

	return armored, nil
}

// EncryptMIME takes a full RFC 5322 message and returns a PGP/MIME encrypted version.
// The body is replaced with a PGP-encrypted version while headers are preserved.
func (p *PGPService) EncryptMIME(message []byte, recipientPublicKey []byte) ([]byte, error) {
	// Separate headers and body
	headerEnd := bytes.Index(message, []byte("\r\n\r\n"))
	sep := []byte("\r\n\r\n")
	if headerEnd == -1 {
		headerEnd = bytes.Index(message, []byte("\n\n"))
		sep = []byte("\n\n")
	}
	if headerEnd == -1 {
		return nil, fmt.Errorf("invalid message format: no header/body separator")
	}

	headers := message[:headerEnd]
	body := message[headerEnd+len(sep):]

	// Encrypt only the body
	encrypted, err := p.EncryptForRecipient(body, recipientPublicKey)
	if err != nil {
		return nil, err
	}

	// Reconstruct message with encrypted body
	var result bytes.Buffer
	result.Write(headers)
	result.WriteString("\r\n")
	// Add PGP content headers
	result.WriteString("Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";\r\n")
	result.WriteString(" boundary=\"ghostmail-pgp-boundary\"\r\n")
	result.WriteString("\r\n")
	result.WriteString("--ghostmail-pgp-boundary\r\n")
	result.WriteString("Content-Type: application/pgp-encrypted\r\n")
	result.WriteString("\r\n")
	result.WriteString("Version: 1\r\n")
	result.WriteString("\r\n")
	result.WriteString("--ghostmail-pgp-boundary\r\n")
	result.WriteString("Content-Type: application/octet-stream\r\n")
	result.WriteString("\r\n")
	result.Write(encrypted)
	result.WriteString("\r\n")
	result.WriteString("--ghostmail-pgp-boundary--\r\n")

	return result.Bytes(), nil
}

// VerifyPGPSignature checks if a message has a valid PGP signature
// from a known key. Returns nil error if signature is valid.
func (p *PGPService) VerifyPGPSignature(message []byte, signerPublicKey []byte) error {
	key, err := crypto.NewKey(signerPublicKey)
	if err != nil {
		return fmt.Errorf("loading signer key: %w", err)
	}

	keyRing, err := crypto.NewKeyRing(key)
	if err != nil {
		return fmt.Errorf("creating keyring: %w", err)
	}

	pgp := crypto.PGP()
	verifyHandle, err := pgp.Decryption().VerificationKeys(keyRing).New()
	if err != nil {
		return fmt.Errorf("creating verification handle: %w", err)
	}

	result, err := verifyHandle.Decrypt(message, crypto.Armor)
	if err != nil {
		return fmt.Errorf("decryption/verification: %w", err)
	}

	if err := result.SignatureError(); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// GeneratePGPKey generates a new PGP keypair for a user.
// Returns armored public key and armored private key.
func GeneratePGPKey(name, email string) (armoredPublic, armoredPrivate string, err error) {
	pgp := crypto.PGP()
	genHandle := pgp.KeyGeneration().AddUserId(name, email).New()

	key, err := genHandle.GenerateKey()
	if err != nil {
		return "", "", fmt.Errorf("generating PGP key: %w", err)
	}

	armoredPrivate, err = key.Armor()
	if err != nil {
		return "", "", fmt.Errorf("armoring private key: %w", err)
	}

	armoredPublic, err = key.GetArmoredPublicKey()
	if err != nil {
		return "", "", fmt.Errorf("armoring public key: %w", err)
	}

	return armoredPublic, armoredPrivate, nil
}
