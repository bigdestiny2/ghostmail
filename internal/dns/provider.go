// Package dns provides automatic DNS record configuration for GhostMail.
// It supports multiple DNS providers (Cloudflare, DigitalOcean, Route53)
// and can auto-detect the provider from a domain's nameservers.
package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// RecordType represents a DNS record type.
type RecordType string

const (
	RecordA     RecordType = "A"
	RecordAAAA  RecordType = "AAAA"
	RecordMX    RecordType = "MX"
	RecordTXT   RecordType = "TXT"
	RecordCNAME RecordType = "CNAME"
)

// Record represents a DNS record to create or verify.
type Record struct {
	Type     RecordType
	Name     string // fully qualified (e.g., "mail.example.com")
	Value    string
	Priority int // MX priority, 0 for non-MX
	TTL      int // seconds, 0 = provider default
}

// Provider is the interface that DNS providers must implement.
type Provider interface {
	// Name returns the provider name (e.g., "cloudflare").
	Name() string

	// CreateRecord creates a DNS record. Returns the record ID on success.
	CreateRecord(ctx context.Context, domain string, rec Record) (string, error)

	// ListRecords returns existing records for the domain filtered by type and name.
	ListRecords(ctx context.Context, domain string, recType RecordType, name string) ([]Record, error)

	// DeleteRecord removes a DNS record by ID.
	DeleteRecord(ctx context.Context, domain string, recordID string) error

	// Verify checks that a record has propagated.
	Verify(ctx context.Context, rec Record) (bool, error)
}

// RequiredRecords generates the full set of DNS records GhostMail needs.
func RequiredRecords(domain, hostname, serverIP, dkimRecord string) []Record {
	if hostname == "" {
		hostname = "mail." + domain
	}

	records := []Record{
		{
			Type:  RecordA,
			Name:  hostname,
			Value: serverIP,
			TTL:   3600,
		},
		{
			Type:     RecordMX,
			Name:     domain,
			Value:    hostname,
			Priority: 10,
			TTL:      3600,
		},
		{
			Type:  RecordTXT,
			Name:  domain,
			Value: "v=spf1 mx a -all",
			TTL:   3600,
		},
		{
			Type:  RecordTXT,
			Name:  "_dmarc." + domain,
			Value: "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s",
			TTL:   3600,
		},
	}

	if dkimRecord != "" {
		records = append(records, Record{
			Type:  RecordTXT,
			Name:  "ghostmail._domainkey." + domain,
			Value: dkimRecord,
			TTL:   3600,
		})
	}

	return records
}

// SetupAll creates all required DNS records for GhostMail using the given provider.
// Returns a list of results for each record (created, skipped, or error).
func SetupAll(ctx context.Context, p Provider, domain, hostname, serverIP, dkimRecord string) ([]SetupResult, error) {
	records := RequiredRecords(domain, hostname, serverIP, dkimRecord)
	results := make([]SetupResult, 0, len(records))

	for _, rec := range records {
		// Check if record already exists
		existing, err := p.ListRecords(ctx, domain, rec.Type, rec.Name)
		if err != nil {
			results = append(results, SetupResult{Record: rec, Status: "error", Error: err})
			continue
		}

		// Check for matching record
		found := false
		for _, e := range existing {
			if strings.EqualFold(e.Value, rec.Value) {
				found = true
				break
			}
		}

		if found {
			results = append(results, SetupResult{Record: rec, Status: "exists"})
			continue
		}

		id, err := p.CreateRecord(ctx, domain, rec)
		if err != nil {
			results = append(results, SetupResult{Record: rec, Status: "error", Error: err})
		} else {
			results = append(results, SetupResult{Record: rec, Status: "created", ID: id})
		}
	}

	return results, nil
}

// SetupResult is the outcome of creating a single DNS record.
type SetupResult struct {
	Record Record
	Status string // "created", "exists", "error"
	ID     string
	Error  error
}

// VerifyAll checks that all required records have propagated.
func VerifyAll(domain, hostname, serverIP string) ([]VerifyResult, error) {
	if hostname == "" {
		hostname = "mail." + domain
	}

	results := make([]VerifyResult, 0)

	// Check A record
	ips, err := net.LookupHost(hostname)
	aOK := false
	if err == nil {
		for _, ip := range ips {
			if ip == serverIP {
				aOK = true
				break
			}
		}
	}
	results = append(results, VerifyResult{
		Type:    RecordA,
		Name:    hostname,
		OK:      aOK,
		Details: fmt.Sprintf("resolved: %v", ips),
	})

	// Check MX record
	mxs, err := net.LookupMX(domain)
	mxOK := false
	if err == nil {
		for _, mx := range mxs {
			if strings.TrimSuffix(mx.Host, ".") == hostname {
				mxOK = true
				break
			}
		}
	}
	mxHosts := make([]string, len(mxs))
	for i, mx := range mxs {
		mxHosts[i] = mx.Host
	}
	results = append(results, VerifyResult{
		Type:    RecordMX,
		Name:    domain,
		OK:      mxOK,
		Details: fmt.Sprintf("mx hosts: %v", mxHosts),
	})

	// Check TXT records (SPF)
	txts, err := net.LookupTXT(domain)
	spfOK := false
	if err == nil {
		for _, txt := range txts {
			if strings.HasPrefix(txt, "v=spf1") {
				spfOK = true
				break
			}
		}
	}
	results = append(results, VerifyResult{
		Type:    RecordTXT,
		Name:    domain + " (SPF)",
		OK:      spfOK,
		Details: fmt.Sprintf("txt records: %v", txts),
	})

	// Check DMARC
	dmarcTxts, err := net.LookupTXT("_dmarc." + domain)
	dmarcOK := false
	if err == nil {
		for _, txt := range dmarcTxts {
			if strings.HasPrefix(txt, "v=DMARC1") {
				dmarcOK = true
				break
			}
		}
	}
	results = append(results, VerifyResult{
		Type:    RecordTXT,
		Name:    "_dmarc." + domain + " (DMARC)",
		OK:      dmarcOK,
		Details: fmt.Sprintf("txt records: %v", dmarcTxts),
	})

	// Check DKIM
	dkimTxts, err := net.LookupTXT("ghostmail._domainkey." + domain)
	dkimOK := false
	if err == nil {
		for _, txt := range dkimTxts {
			if strings.Contains(txt, "p=") {
				dkimOK = true
				break
			}
		}
	}
	results = append(results, VerifyResult{
		Type:    RecordTXT,
		Name:    "ghostmail._domainkey." + domain + " (DKIM)",
		OK:      dkimOK,
		Details: fmt.Sprintf("txt records: %v", dkimTxts),
	})

	return results, nil
}

// VerifyResult is the outcome of verifying a single DNS record.
type VerifyResult struct {
	Type    RecordType
	Name    string
	OK      bool
	Details string
}
