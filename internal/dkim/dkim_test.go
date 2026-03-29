package dkim

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestGenerateRSAKey(t *testing.T) {
	privPEM, dnsRecord, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	if len(privPEM) == 0 {
		t.Error("empty private key PEM")
	}
	if !strings.Contains(string(privPEM), "RSA PRIVATE KEY") {
		t.Error("PEM should contain RSA PRIVATE KEY header")
	}
	if !strings.HasPrefix(dnsRecord, "v=DKIM1; k=rsa; p=") {
		t.Errorf("unexpected DNS record format: %s", dnsRecord)
	}
}

func TestGenerateEd25519Key(t *testing.T) {
	privKey, dnsRecord, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	if len(privKey) != ed25519.PrivateKeySize {
		t.Errorf("private key size = %d, want %d", len(privKey), ed25519.PrivateKeySize)
	}
	if !strings.HasPrefix(dnsRecord, "v=DKIM1; k=ed25519; p=") {
		t.Errorf("unexpected DNS record format: %s", dnsRecord)
	}
}

func TestRSASignAndVerify(t *testing.T) {
	privPEM, _, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewRSASigner("example.com", "test", privPEM)
	if err != nil {
		t.Fatal("creating signer:", err)
	}

	msg := []byte("From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Test\r\nDate: Sat, 29 Mar 2026 12:00:00 +0000\r\nMessage-ID: <test@example.com>\r\n\r\nHello World")

	signed, err := signer.Sign(msg)
	if err != nil {
		t.Fatal("signing:", err)
	}

	// Signed message should contain DKIM-Signature header
	if !bytes.Contains(signed, []byte("DKIM-Signature:")) {
		t.Error("signed message should contain DKIM-Signature header")
	}

	// Signed message should still contain original headers and body
	if !bytes.Contains(signed, []byte("From: alice@example.com")) {
		t.Error("signed message should preserve From header")
	}
	if !bytes.Contains(signed, []byte("Hello World")) {
		t.Error("signed message should preserve body")
	}

	if signer.Domain() != "example.com" {
		t.Errorf("domain = %q, want example.com", signer.Domain())
	}
}

func TestEd25519SignAndVerify(t *testing.T) {
	privKey, _, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewEd25519Signer("example.com", "ed", privKey)
	if err != nil {
		t.Fatal("creating signer:", err)
	}

	msg := []byte("From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Test\r\nDate: Sat, 29 Mar 2026 12:00:00 +0000\r\nMessage-ID: <test@example.com>\r\n\r\nHello World")

	signed, err := signer.Sign(msg)
	if err != nil {
		t.Fatal("signing:", err)
	}

	if !bytes.Contains(signed, []byte("DKIM-Signature:")) {
		t.Error("signed message should contain DKIM-Signature header")
	}
}

func TestFormatDNSRecords(t *testing.T) {
	dkim := FormatDNSRecord("ghostmail", "example.com", "v=DKIM1; k=rsa; p=AAAA")
	if !strings.Contains(dkim, "ghostmail._domainkey.example.com") {
		t.Errorf("unexpected DKIM record: %s", dkim)
	}

	spf := FormatSPFRecord("example.com")
	if !strings.Contains(spf, "v=spf1") {
		t.Errorf("unexpected SPF record: %s", spf)
	}

	dmarc := FormatDMARCRecord("example.com", "admin@example.com")
	if !strings.Contains(dmarc, "v=DMARC1") || !strings.Contains(dmarc, "rua=mailto:") {
		t.Errorf("unexpected DMARC record: %s", dmarc)
	}

	dmarcNoReport := FormatDMARCRecord("example.com", "")
	if strings.Contains(dmarcNoReport, "rua=") {
		t.Error("DMARC without report email should not have rua")
	}
}

func TestVerifyInbound(t *testing.T) {
	// Message without DKIM should return "none"
	msg := []byte("From: alice@example.com\r\nTo: bob@test.com\r\n\r\nHello")
	result := VerifyInbound(msg)
	if result.DKIM != "none" {
		t.Errorf("expected DKIM=none for unsigned message, got %s", result.DKIM)
	}
}

func TestAuthResultsHeader(t *testing.T) {
	auth := &AuthResult{DKIM: "pass", SPF: "none", DMARC: "none", Domain: "example.com"}
	header := FormatAuthResultsHeader("mail.test.com", auth)
	if !strings.Contains(header, "dkim=pass") {
		t.Error("should contain dkim=pass")
	}
	if !strings.Contains(header, "header.d=example.com") {
		t.Error("should contain header.d=example.com")
	}
	if !strings.Contains(header, "mail.test.com") {
		t.Error("should contain hostname")
	}
}

func TestAddAuthResultsHeader(t *testing.T) {
	msg := []byte("From: alice@example.com\r\n\r\nBody")
	auth := &AuthResult{DKIM: "pass", Domain: "example.com"}
	result := AddAuthResultsHeader(msg, "mail.test.com", auth)

	if !bytes.HasPrefix(result, []byte("Authentication-Results:")) {
		t.Error("result should start with Authentication-Results")
	}
	if !bytes.Contains(result, []byte("From: alice@example.com")) {
		t.Error("original headers should be preserved")
	}
}

func TestStripExistingAuthResults(t *testing.T) {
	msg := []byte("Authentication-Results: evil.com; dkim=pass\r\nFrom: alice@example.com\r\nSubject: Hi\r\n\r\nBody")
	stripped := StripExistingAuthResults(msg)

	if bytes.Contains(stripped, []byte("evil.com")) {
		t.Error("existing Authentication-Results should be stripped")
	}
	if !bytes.Contains(stripped, []byte("From: alice@example.com")) {
		t.Error("other headers should be preserved")
	}
	if !bytes.Contains(stripped, []byte("Body")) {
		t.Error("body should be preserved")
	}
}

func TestVerificationSummary(t *testing.T) {
	s := VerificationSummary(nil)
	if s != "none" {
		t.Errorf("empty verifications should return 'none', got %q", s)
	}
}
