package spf

import (
	"fmt"
	"net"
	"testing"
)

// fakeResolver implements Resolver for deterministic unit tests.
type fakeResolver struct {
	txt map[string][]string
	ips map[string][]net.IP
	mx  map[string][]*net.MX
}

func (f *fakeResolver) LookupTXT(domain string) ([]string, error) {
	if recs, ok := f.txt[domain]; ok {
		return recs, nil
	}
	return nil, fmt.Errorf("no TXT for %s", domain)
}

func (f *fakeResolver) LookupIPAddr(host string) ([]net.IP, error) {
	if ips, ok := f.ips[host]; ok {
		return ips, nil
	}
	return nil, fmt.Errorf("no A/AAAA for %s", host)
}

func (f *fakeResolver) LookupMX(domain string) ([]*net.MX, error) {
	if mxs, ok := f.mx[domain]; ok {
		return mxs, nil
	}
	return nil, fmt.Errorf("no MX for %s", domain)
}

func TestCheckNoSPFRecord(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{}}
	result := CheckWithResolver(net.ParseIP("1.2.3.4"), "example.com", r)
	if result != ResultNone {
		t.Errorf("expected none, got %s", result)
	}
}

func TestCheckIP4Pass(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"example.com": {"v=spf1 ip4:1.2.3.4 -all"},
		},
	}
	result := CheckWithResolver(net.ParseIP("1.2.3.4"), "example.com", r)
	if result != ResultPass {
		t.Errorf("expected pass, got %s", result)
	}
}

func TestCheckIP4Fail(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"example.com": {"v=spf1 ip4:1.2.3.4 -all"},
		},
	}
	result := CheckWithResolver(net.ParseIP("5.6.7.8"), "example.com", r)
	if result != ResultFail {
		t.Errorf("expected fail, got %s", result)
	}
}

func TestCheckIP4CIDR(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"example.com": {"v=spf1 ip4:10.0.0.0/8 -all"},
		},
	}
	// IP within range
	result := CheckWithResolver(net.ParseIP("10.1.2.3"), "example.com", r)
	if result != ResultPass {
		t.Errorf("expected pass for 10.1.2.3, got %s", result)
	}
	// IP outside range
	result = CheckWithResolver(net.ParseIP("11.0.0.1"), "example.com", r)
	if result != ResultFail {
		t.Errorf("expected fail for 11.0.0.1, got %s", result)
	}
}

func TestCheckIP6(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"example.com": {"v=spf1 ip6:2001:db8::1 -all"},
		},
	}
	result := CheckWithResolver(net.ParseIP("2001:db8::1"), "example.com", r)
	if result != ResultPass {
		t.Errorf("expected pass, got %s", result)
	}
	result = CheckWithResolver(net.ParseIP("2001:db8::2"), "example.com", r)
	if result != ResultFail {
		t.Errorf("expected fail, got %s", result)
	}
}

func TestCheckMX(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"example.com": {"v=spf1 mx -all"},
		},
		mx: map[string][]*net.MX{
			"example.com": {{Host: "mail.example.com.", Pref: 10}},
		},
		ips: map[string][]net.IP{
			"mail.example.com": {net.ParseIP("93.184.216.34")},
		},
	}
	result := CheckWithResolver(net.ParseIP("93.184.216.34"), "example.com", r)
	if result != ResultPass {
		t.Errorf("expected pass via MX, got %s", result)
	}
	result = CheckWithResolver(net.ParseIP("1.1.1.1"), "example.com", r)
	if result != ResultFail {
		t.Errorf("expected fail for non-MX IP, got %s", result)
	}
}

func TestCheckA(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"example.com": {"v=spf1 a -all"},
		},
		ips: map[string][]net.IP{
			"example.com": {net.ParseIP("93.184.216.34")},
		},
	}
	result := CheckWithResolver(net.ParseIP("93.184.216.34"), "example.com", r)
	if result != ResultPass {
		t.Errorf("expected pass via A, got %s", result)
	}
}

func TestCheckAWithDomain(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"example.com": {"v=spf1 a:other.example.com -all"},
		},
		ips: map[string][]net.IP{
			"other.example.com": {net.ParseIP("10.0.0.1")},
		},
	}
	result := CheckWithResolver(net.ParseIP("10.0.0.1"), "example.com", r)
	if result != ResultPass {
		t.Errorf("expected pass via a:other.example.com, got %s", result)
	}
}

func TestCheckInclude(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"example.com":  {"v=spf1 include:_spf.google.com -all"},
			"_spf.google.com": {"v=spf1 ip4:172.217.0.0/16 -all"},
		},
	}
	result := CheckWithResolver(net.ParseIP("172.217.1.1"), "example.com", r)
	if result != ResultPass {
		t.Errorf("expected pass via include, got %s", result)
	}
	result = CheckWithResolver(net.ParseIP("8.8.8.8"), "example.com", r)
	if result != ResultFail {
		t.Errorf("expected fail, got %s", result)
	}
}

func TestCheckSoftFail(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"example.com": {"v=spf1 ip4:1.2.3.4 ~all"},
		},
	}
	result := CheckWithResolver(net.ParseIP("5.6.7.8"), "example.com", r)
	if result != ResultSoftFail {
		t.Errorf("expected softfail, got %s", result)
	}
}

func TestCheckNeutral(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"example.com": {"v=spf1 ip4:1.2.3.4 ?all"},
		},
	}
	result := CheckWithResolver(net.ParseIP("5.6.7.8"), "example.com", r)
	if result != ResultNeutral {
		t.Errorf("expected neutral, got %s", result)
	}
}

func TestCheckPlusAll(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"example.com": {"v=spf1 +all"},
		},
	}
	result := CheckWithResolver(net.ParseIP("99.99.99.99"), "example.com", r)
	if result != ResultPass {
		t.Errorf("expected pass for +all, got %s", result)
	}
}

func TestIncludeDepthLimit(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"a.com": {"v=spf1 include:b.com -all"},
			"b.com": {"v=spf1 include:c.com -all"},
			"c.com": {"v=spf1 include:d.com -all"},
			"d.com": {"v=spf1 include:e.com -all"},
			"e.com": {"v=spf1 ip4:1.2.3.4 -all"},
		},
	}
	// Should hit depth limit before reaching e.com
	result := CheckWithResolver(net.ParseIP("1.2.3.4"), "a.com", r)
	// The include chain is a(0)->b(1)->c(2)->d(3)->e(4), depth > 3 returns temperror
	// which is not "pass" so include doesn't match, falls through to -all = fail
	if result != ResultFail {
		t.Errorf("expected fail due to depth limit, got %s", result)
	}
}

func TestCheckMultipleTXTRecords(t *testing.T) {
	// Domain has multiple TXT records but only one is SPF
	r := &fakeResolver{
		txt: map[string][]string{
			"example.com": {
				"google-site-verification=abc123",
				"v=spf1 ip4:1.2.3.4 -all",
			},
		},
	}
	result := CheckWithResolver(net.ParseIP("1.2.3.4"), "example.com", r)
	if result != ResultPass {
		t.Errorf("expected pass, got %s", result)
	}
}

func TestParseQualifier(t *testing.T) {
	tests := []struct {
		token     string
		wantQ     byte
		wantMech  string
	}{
		{"ip4:1.2.3.4", '+', "ip4:1.2.3.4"},
		{"+ip4:1.2.3.4", '+', "ip4:1.2.3.4"},
		{"-all", '-', "all"},
		{"~all", '~', "all"},
		{"?all", '?', "all"},
		{"MX", '+', "mx"},
	}

	for _, tt := range tests {
		q, m := parseQualifier(tt.token)
		if q != tt.wantQ || m != tt.wantMech {
			t.Errorf("parseQualifier(%q) = (%c, %q), want (%c, %q)",
				tt.token, q, m, tt.wantQ, tt.wantMech)
		}
	}
}
