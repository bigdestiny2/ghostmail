// Package dkim provides DKIM signing and DKIM/SPF/DMARC verification.
package dkim

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
)

// SignedHeaders are the headers included in the DKIM signature.
var SignedHeaders = []string{
	"From", "To", "Subject", "Date", "Message-ID",
	"MIME-Version", "Content-Type", "Content-Transfer-Encoding",
	"Reply-To", "Cc", "In-Reply-To", "References",
}

// Signer handles DKIM signing of outbound messages.
type Signer struct {
	domain    string
	selector  string
	signer    crypto.Signer
	algorithm string // "rsa" or "ed25519"
}

// NewRSASigner creates a DKIM signer using an RSA private key.
func NewRSASigner(domain, selector string, privateKeyPEM []byte) (*Signer, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		k, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parsing RSA key: %w (PKCS8: %w)", err, err2)
		}
		rsaKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not RSA")
		}
		key = rsaKey
	}

	return &Signer{
		domain:    domain,
		selector:  selector,
		signer:    key,
		algorithm: "rsa",
	}, nil
}

// NewEd25519Signer creates a DKIM signer using an Ed25519 private key.
func NewEd25519Signer(domain, selector string, privateKey ed25519.PrivateKey) (*Signer, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size: %d", len(privateKey))
	}
	return &Signer{
		domain:    domain,
		selector:  selector,
		signer:    privateKey,
		algorithm: "ed25519",
	}, nil
}

// Sign adds a DKIM-Signature header to the message.
// Returns the signed message bytes.
func (s *Signer) Sign(message []byte) ([]byte, error) {
	opts := &dkim.SignOptions{
		Domain:   s.domain,
		Selector: s.selector,
		Signer:   s.signer,
		HeaderKeys: SignedHeaders,
	}

	var signed bytes.Buffer
	if err := dkim.Sign(&signed, bytes.NewReader(message), opts); err != nil {
		return nil, fmt.Errorf("DKIM signing: %w", err)
	}

	return signed.Bytes(), nil
}

// Domain returns the signer's domain.
func (s *Signer) Domain() string {
	return s.domain
}

// --- Key Generation ---

// GenerateRSAKey generates an RSA keypair for DKIM signing.
// Returns PEM-encoded private key and the DNS TXT record value for the public key.
func GenerateRSAKey(bits int) (privateKeyPEM []byte, dnsRecord string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, "", fmt.Errorf("generating RSA key: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("marshaling public key: %w", err)
	}

	pubB64 := base64.StdEncoding.EncodeToString(pubDER)
	dnsRecord = fmt.Sprintf("v=DKIM1; k=rsa; p=%s", pubB64)

	return privPEM, dnsRecord, nil
}

// GenerateEd25519Key generates an Ed25519 keypair for DKIM signing.
// Returns the raw private key and the DNS TXT record value.
func GenerateEd25519Key() (privateKey ed25519.PrivateKey, dnsRecord string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generating Ed25519 key: %w", err)
	}

	pubB64 := base64.StdEncoding.EncodeToString(pub)
	dnsRecord = fmt.Sprintf("v=DKIM1; k=ed25519; p=%s", pubB64)

	return priv, dnsRecord, nil
}

// FormatDNSRecord formats a DKIM DNS TXT record with selector and domain.
func FormatDNSRecord(selector, domain, record string) string {
	return fmt.Sprintf("%s._domainkey.%s  IN  TXT  \"%s\"", selector, domain, record)
}

// FormatSPFRecord returns a recommended SPF record.
func FormatSPFRecord(domain string) string {
	return fmt.Sprintf("%s  IN  TXT  \"v=spf1 mx a -all\"", domain)
}

// FormatDMARCRecord returns a recommended DMARC record.
func FormatDMARCRecord(domain, reportEmail string) string {
	if reportEmail == "" {
		return fmt.Sprintf("_dmarc.%s  IN  TXT  \"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s\"", domain)
	}
	return fmt.Sprintf("_dmarc.%s  IN  TXT  \"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:%s\"",
		domain, reportEmail)
}

// ParseDKIMPublicKeyPEM extracts the public key portion for DNS from a PEM private key.
func ParseDKIMPublicKeyPEM(privateKeyPEM []byte) (string, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(pubDER), nil
}

// VerifyReader verifies DKIM signatures on a message and returns results.
func VerifyReader(r io.Reader) ([]*dkim.Verification, error) {
	return dkim.Verify(r)
}

// VerifyMessage verifies DKIM signatures on raw message bytes.
func VerifyMessage(message []byte) ([]*dkim.Verification, error) {
	return dkim.Verify(bytes.NewReader(message))
}

// VerificationSummary returns a human-readable summary of DKIM verification.
func VerificationSummary(verifications []*dkim.Verification) string {
	if len(verifications) == 0 {
		return "none"
	}
	var parts []string
	for _, v := range verifications {
		status := "pass"
		if v.Err != nil {
			status = fmt.Sprintf("fail (%v)", v.Err)
		}
		parts = append(parts, fmt.Sprintf("%s: %s", v.Domain, status))
	}
	return strings.Join(parts, "; ")
}
