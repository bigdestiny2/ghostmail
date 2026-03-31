package dmarc

import (
	"fmt"
	"testing"
)

// fakeResolver implements Resolver for deterministic unit tests.
type fakeResolver struct {
	txt map[string][]string
}

func (f *fakeResolver) LookupTXT(domain string) ([]string, error) {
	if recs, ok := f.txt[domain]; ok {
		return recs, nil
	}
	return nil, fmt.Errorf("no TXT for %s", domain)
}

func TestCheckNoRecord(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{}}
	result := CheckWithResolver("example.com", "pass", "example.com", "none", "", r)
	if result.HasRecord {
		t.Error("expected HasRecord=false")
	}
	if result.Pass {
		t.Error("expected Pass=false without record")
	}
	if result.Policy != PolicyNone {
		t.Errorf("expected policy none, got %s", result.Policy)
	}
}

func TestCheckRejectPolicy_SPFAligned(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"_dmarc.example.com": {"v=DMARC1; p=reject; adkim=s; aspf=s"},
		},
	}
	result := CheckWithResolver("example.com", "pass", "example.com", "none", "", r)
	if !result.HasRecord {
		t.Error("expected HasRecord=true")
	}
	if result.Policy != PolicyReject {
		t.Errorf("expected reject, got %s", result.Policy)
	}
	if !result.Pass {
		t.Error("expected pass (SPF aligned strict)")
	}
}

func TestCheckRejectPolicy_DKIMAligned(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"_dmarc.example.com": {"v=DMARC1; p=reject"},
		},
	}
	result := CheckWithResolver("example.com", "fail", "other.com", "pass", "example.com", r)
	if !result.Pass {
		t.Error("expected pass (DKIM aligned relaxed)")
	}
}

func TestCheckRejectPolicy_Fail(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"_dmarc.example.com": {"v=DMARC1; p=reject"},
		},
	}
	// SPF passes but domain doesn't align, DKIM fails
	result := CheckWithResolver("example.com", "pass", "other.com", "fail", "example.com", r)
	if result.Pass {
		t.Error("expected fail (SPF domain misaligned)")
	}
}

func TestCheckQuarantinePolicy(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"_dmarc.example.com": {"v=DMARC1; p=quarantine"},
		},
	}
	result := CheckWithResolver("example.com", "fail", "example.com", "none", "", r)
	if result.Policy != PolicyQuarantine {
		t.Errorf("expected quarantine, got %s", result.Policy)
	}
	if result.Pass {
		t.Error("expected fail (SPF failed)")
	}
}

func TestCheckRelaxedAlignment(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"_dmarc.example.com": {"v=DMARC1; p=reject; aspf=r"},
		},
	}
	// SPF passes for sub.example.com, From is example.com — relaxed alignment
	result := CheckWithResolver("example.com", "pass", "sub.example.com", "none", "", r)
	if !result.Pass {
		t.Error("expected pass (relaxed SPF alignment for subdomain)")
	}
}

func TestCheckStrictAlignment_SubdomainFails(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"_dmarc.example.com": {"v=DMARC1; p=reject; aspf=s"},
		},
	}
	// SPF passes for sub.example.com, From is example.com — strict should fail
	result := CheckWithResolver("example.com", "pass", "sub.example.com", "none", "", r)
	if result.Pass {
		t.Error("expected fail (strict SPF alignment rejects subdomain)")
	}
}

func TestCheckDKIMStrictAlignment(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"_dmarc.example.com": {"v=DMARC1; p=reject; adkim=s"},
		},
	}
	// DKIM passes for sub.example.com — strict should fail
	result := CheckWithResolver("example.com", "none", "", "pass", "sub.example.com", r)
	if result.Pass {
		t.Error("expected fail (strict DKIM alignment rejects subdomain)")
	}
	// DKIM passes for exact match — strict should pass
	result = CheckWithResolver("example.com", "none", "", "pass", "example.com", r)
	if !result.Pass {
		t.Error("expected pass (strict DKIM alignment exact match)")
	}
}

func TestParseTags(t *testing.T) {
	tags := parseTags("v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:admin@example.com")
	if tags["p"] != "reject" {
		t.Errorf("p = %q, want reject", tags["p"])
	}
	if tags["adkim"] != "s" {
		t.Errorf("adkim = %q, want s", tags["adkim"])
	}
	if tags["aspf"] != "s" {
		t.Errorf("aspf = %q, want s", tags["aspf"])
	}
	if tags["rua"] != "mailto:admin@example.com" {
		t.Errorf("rua = %q", tags["rua"])
	}
}

func TestOrgDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"a.b.example.com", "example.com"},
		{"localhost", "localhost"},
	}
	for _, tt := range tests {
		got := orgDomain(tt.domain)
		if got != tt.want {
			t.Errorf("orgDomain(%q) = %q, want %q", tt.domain, got, tt.want)
		}
	}
}

func TestCheckNonePolicy_NoEnforcement(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"_dmarc.example.com": {"v=DMARC1; p=none"},
		},
	}
	result := CheckWithResolver("example.com", "fail", "example.com", "none", "", r)
	if result.Policy != PolicyNone {
		t.Errorf("expected none, got %s", result.Policy)
	}
	if result.Pass {
		t.Error("expected fail (SPF failed)")
	}
	if !result.HasRecord {
		t.Error("expected HasRecord=true")
	}
}
