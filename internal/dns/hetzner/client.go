// Package hetzner implements a DNS provider client for the Hetzner DNS API.
//
// API docs: https://dns.hetzner.com/api-docs
// Base URL: https://dns.hetzner.com/api/v1
package hetzner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sisumail/sisumail/internal/core"
)

const defaultBaseURL = "https://dns.hetzner.com/api/v1"

// Client implements core.DNSProvider using the Hetzner DNS API.
type Client struct {
	BaseURL    string
	APIToken   string
	HTTPClient *http.Client
}

// NewClient creates a new Hetzner DNS client.
func NewClient(apiToken string) *Client {
	return &Client{
		BaseURL:  defaultBaseURL,
		APIToken: apiToken,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// --- API request/response types ---

type apiRecord struct {
	ID     string `json:"id,omitempty"`
	Type   string `json:"type"`
	Name   string `json:"name"`
	Value  string `json:"value"`
	TTL    int    `json:"ttl,omitempty"`
	ZoneID string `json:"zone_id"`
}

type createRecordRequest struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Value  string `json:"value"`
	TTL    int    `json:"ttl,omitempty"`
	ZoneID string `json:"zone_id"`
}

type createRecordResponse struct {
	Record apiRecord `json:"record"`
}

type listRecordsResponse struct {
	Records []apiRecord `json:"records"`
}

type getZonesResponse struct {
	Zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"zones"`
}

type apiError struct {
	Error struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	} `json:"error"`
}

// --- core.DNSProvider implementation ---

// GetZoneIDByName returns the zone ID for the given zone name (e.g. "sisumail.fi").
func (c *Client) GetZoneIDByName(zoneName string) (string, error) {
	req, err := c.newRequest(http.MethodGet, "/zones?name="+zoneName, nil)
	if err != nil {
		return "", err
	}
	var resp getZonesResponse
	if err := c.do(req, &resp); err != nil {
		return "", fmt.Errorf("get zone %q: %w", zoneName, err)
	}
	for _, z := range resp.Zones {
		if z.Name == zoneName {
			return z.ID, nil
		}
	}
	return "", fmt.Errorf("zone %q not found", zoneName)
}

// CreateRecord creates a DNS record and returns its ID.
func (c *Client) CreateRecord(zoneID string, rec core.DNSRecord) (string, error) {
	body := createRecordRequest{
		Type:   rec.Type,
		Name:   rec.Name,
		Value:  rec.Value,
		TTL:    rec.TTL,
		ZoneID: zoneID,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := c.newRequest(http.MethodPost, "/records", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	var resp createRecordResponse
	if err := c.do(req, &resp); err != nil {
		return "", fmt.Errorf("create record %s %s: %w", rec.Type, rec.Name, err)
	}
	return resp.Record.ID, nil
}

// DeleteRecord deletes a DNS record by ID.
func (c *Client) DeleteRecord(zoneID, recordID string) error {
	req, err := c.newRequest(http.MethodDelete, "/records/"+recordID, nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

// ListRecords lists DNS records in a zone, optionally filtered by name.
func (c *Client) ListRecords(zoneID, name string) ([]core.DNSRecordEntry, error) {
	path := fmt.Sprintf("/records?zone_id=%s", zoneID)
	req, err := c.newRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var resp listRecordsResponse
	if err := c.do(req, &resp); err != nil {
		return nil, fmt.Errorf("list records zone=%s: %w", zoneID, err)
	}
	var out []core.DNSRecordEntry
	for _, r := range resp.Records {
		if name != "" && r.Name != name {
			continue
		}
		out = append(out, core.DNSRecordEntry{
			ID:    r.ID,
			Type:  r.Type,
			Name:  r.Name,
			Value: r.Value,
			TTL:   r.TTL,
		})
	}
	return out, nil
}

// --- HTTP helpers ---

func (c *Client) newRequest(method, path string, body io.Reader) (*http.Request, error) {
	url := c.BaseURL + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Auth-API-Token", c.APIToken)
	return req, nil
}

func (c *Client) do(req *http.Request, result interface{}) error {
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr apiError
		_ = json.Unmarshal(respBody, &apiErr)
		if apiErr.Error.Message != "" {
			return fmt.Errorf("hetzner api %d: %s", resp.StatusCode, apiErr.Error.Message)
		}
		return fmt.Errorf("hetzner api %d: %s", resp.StatusCode, string(respBody))
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
