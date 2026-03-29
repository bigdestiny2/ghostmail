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

// Cloudflare implements the Provider interface for Cloudflare DNS API.
type Cloudflare struct {
	apiToken string
	client   *http.Client
	baseURL  string
}

// NewCloudflare creates a Cloudflare DNS provider using an API token.
func NewCloudflare(apiToken string) *Cloudflare {
	return &Cloudflare{
		apiToken: apiToken,
		client:   &http.Client{},
		baseURL:  "https://api.cloudflare.com/client/v4",
	}
}

func (c *Cloudflare) Name() string { return "cloudflare" }

// cfZone is the Cloudflare zone response structure.
type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfResult struct {
	Success bool            `json:"success"`
	Errors  []cfError       `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfRecord struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	Priority int    `json:"priority,omitempty"`
	TTL      int    `json:"ttl"`
}

func (c *Cloudflare) do(ctx context.Context, method, path string, body interface{}) (json.RawMessage, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var result cfResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w (status %d)", err, resp.StatusCode)
	}

	if !result.Success {
		msgs := make([]string, len(result.Errors))
		for i, e := range result.Errors {
			msgs[i] = e.Message
		}
		return nil, fmt.Errorf("cloudflare API error: %s", strings.Join(msgs, "; "))
	}

	return result.Result, nil
}

func (c *Cloudflare) getZoneID(ctx context.Context, domain string) (string, error) {
	data, err := c.do(ctx, "GET", "/zones?name="+domain, nil)
	if err != nil {
		return "", err
	}

	var zones []cfZone
	if err := json.Unmarshal(data, &zones); err != nil {
		return "", err
	}

	if len(zones) == 0 {
		return "", fmt.Errorf("no Cloudflare zone found for %s — is the domain added to your Cloudflare account?", domain)
	}

	return zones[0].ID, nil
}

func (c *Cloudflare) CreateRecord(ctx context.Context, domain string, rec Record) (string, error) {
	zoneID, err := c.getZoneID(ctx, domain)
	if err != nil {
		return "", err
	}

	body := map[string]interface{}{
		"type":    string(rec.Type),
		"name":    rec.Name,
		"content": rec.Value,
		"ttl":     rec.TTL,
	}
	if rec.Type == RecordMX {
		body["priority"] = rec.Priority
	}

	data, err := c.do(ctx, "POST", "/zones/"+zoneID+"/dns_records", body)
	if err != nil {
		return "", err
	}

	var created cfRecord
	if err := json.Unmarshal(data, &created); err != nil {
		return "", err
	}

	return created.ID, nil
}

func (c *Cloudflare) ListRecords(ctx context.Context, domain string, recType RecordType, name string) ([]Record, error) {
	zoneID, err := c.getZoneID(ctx, domain)
	if err != nil {
		return nil, err
	}

	path := fmt.Sprintf("/zones/%s/dns_records?type=%s&name=%s", zoneID, string(recType), name)
	data, err := c.do(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var cfRecs []cfRecord
	if err := json.Unmarshal(data, &cfRecs); err != nil {
		return nil, err
	}

	records := make([]Record, len(cfRecs))
	for i, r := range cfRecs {
		records[i] = Record{
			Type:     RecordType(r.Type),
			Name:     r.Name,
			Value:    r.Content,
			Priority: r.Priority,
			TTL:      r.TTL,
		}
	}

	return records, nil
}

func (c *Cloudflare) DeleteRecord(ctx context.Context, domain string, recordID string) error {
	zoneID, err := c.getZoneID(ctx, domain)
	if err != nil {
		return err
	}

	_, err = c.do(ctx, "DELETE", "/zones/"+zoneID+"/dns_records/"+recordID, nil)
	return err
}

func (c *Cloudflare) Verify(ctx context.Context, rec Record) (bool, error) {
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
