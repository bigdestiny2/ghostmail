package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// DigitalOcean implements the Provider interface for DigitalOcean DNS API.
type DigitalOcean struct {
	apiToken string
	client   *http.Client
	baseURL  string
}

// NewDigitalOcean creates a DigitalOcean DNS provider using a personal access token.
func NewDigitalOcean(apiToken string) *DigitalOcean {
	return &DigitalOcean{
		apiToken: apiToken,
		client:   &http.Client{},
		baseURL:  "https://api.digitalocean.com/v2",
	}
}

func (d *DigitalOcean) Name() string { return "digitalocean" }

type doRecord struct {
	ID       int    `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Data     string `json:"data"`
	Priority int    `json:"priority,omitempty"`
	TTL      int    `json:"ttl"`
}

type doRecordsResp struct {
	DomainRecords []doRecord `json:"domain_records"`
}

type doRecordResp struct {
	DomainRecord doRecord `json:"domain_record"`
}

func (d *DigitalOcean) do(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, d.baseURL+path, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+d.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("digitalocean request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("digitalocean API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// relativeName converts "mail.example.com" to "mail" for DO's API
// which expects names relative to the domain.
func relativeName(fqdn, domain string) string {
	name := strings.TrimSuffix(fqdn, "."+domain)
	if name == domain {
		return "@"
	}
	return name
}

func (d *DigitalOcean) CreateRecord(ctx context.Context, domain string, rec Record) (string, error) {
	body := map[string]interface{}{
		"type": string(rec.Type),
		"name": relativeName(rec.Name, domain),
		"data": rec.Value,
		"ttl":  rec.TTL,
	}
	if rec.Type == RecordMX {
		body["priority"] = rec.Priority
		// DO wants the MX target with trailing dot
		if !strings.HasSuffix(rec.Value, ".") {
			body["data"] = rec.Value + "."
		}
	}

	respBody, err := d.do(ctx, "POST", "/domains/"+domain+"/records", body)
	if err != nil {
		return "", err
	}

	var resp doRecordResp
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", err
	}

	return fmt.Sprintf("%d", resp.DomainRecord.ID), nil
}

func (d *DigitalOcean) ListRecords(ctx context.Context, domain string, recType RecordType, name string) ([]Record, error) {
	relName := relativeName(name, domain)
	path := fmt.Sprintf("/domains/%s/records?type=%s&name=%s&per_page=100", domain, string(recType), relName)

	respBody, err := d.do(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var resp doRecordsResp
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, err
	}

	records := make([]Record, 0, len(resp.DomainRecords))
	for _, r := range resp.DomainRecords {
		fqdn := r.Name
		if fqdn != domain && !strings.HasSuffix(fqdn, "."+domain) {
			fqdn = r.Name + "." + domain
		}
		records = append(records, Record{
			Type:     RecordType(r.Type),
			Name:     fqdn,
			Value:    strings.TrimSuffix(r.Data, "."),
			Priority: r.Priority,
			TTL:      r.TTL,
		})
	}

	return records, nil
}

func (d *DigitalOcean) DeleteRecord(ctx context.Context, domain string, recordID string) error {
	_, err := d.do(ctx, "DELETE", fmt.Sprintf("/domains/%s/records/%s", domain, recordID), nil)
	return err
}

func (d *DigitalOcean) Verify(ctx context.Context, rec Record) (bool, error) {
	results, err := VerifyAll(rec.Name, "", rec.Value)
	if err != nil {
		return false, err
	}
	for _, r := range results {
		if r.Name == rec.Name && r.OK {
			return true, nil
		}
	}
	return false, nil
}
