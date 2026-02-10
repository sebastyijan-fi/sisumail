// Package hetznercloud implements DNS operations using the Hetzner Cloud API
// (Hetzner Console DNS).
//
// Base URL: https://api.hetzner.cloud/v1
// Auth: Authorization: Bearer <token>
//
// This intentionally does NOT use the deprecated dns.hetzner.com API.
package hetznercloud

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sisumail/sisumail/internal/core"
)

const defaultBaseURL = "https://api.hetzner.cloud/v1"

// Client implements core.DNSProvider using the Hetzner Cloud Zones API.
type Client struct {
	BaseURL    string
	APIToken   string
	ZoneName   string // e.g. "sisumail.fi"
	HTTPClient *http.Client
}

func NewClient(apiToken, zoneName string) *Client {
	return &Client{
		BaseURL:  defaultBaseURL,
		APIToken: apiToken,
		ZoneName: strings.TrimSuffix(zoneName, "."),
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

type apiZone struct {
	ID   zoneID `json:"id"`
	Name string `json:"name"`
}

type listZonesResponse struct {
	Zones []apiZone `json:"zones"`
}

// zoneID accepts either a JSON string or a JSON number and canonicalizes to string.
// Hetzner Console DNS zones have been observed to return numeric IDs.
type zoneID string

func (z *zoneID) UnmarshalJSON(b []byte) error {
	// Try string first.
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*z = zoneID(s)
		return nil
	}
	// Then number.
	var n json.Number
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&n); err == nil {
		*z = zoneID(n.String())
		return nil
	}
	return fmt.Errorf("invalid zone id: %s", string(b))
}

type apiRRSetRecord struct {
	Value   string `json:"value"`
	Comment string `json:"comment,omitempty"`
}

type apiRRSet struct {
	Name    string           `json:"name"`
	Type    string           `json:"type"`
	TTL     int              `json:"ttl,omitempty"`
	Records []apiRRSetRecord `json:"records"`
}

type listRRSetsResponse struct {
	RRSets []apiRRSet `json:"rrsets"`
}

type createRRSetRequest struct {
	Name    string           `json:"name"`
	Type    string           `json:"type"`
	TTL     int              `json:"ttl,omitempty"`
	Records []apiRRSetRecord `json:"records"`
}

type rrsetActionRequest struct {
	Records []apiRRSetRecord `json:"records"`
}

type apiError struct {
	Error struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	} `json:"error"`
}

func (c *Client) GetZoneIDByName(zoneName string) (string, error) {
	q := url.Values{}
	q.Set("name", strings.TrimSuffix(zoneName, "."))
	req, err := c.newRequest(http.MethodGet, "/zones?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	var resp listZonesResponse
	if err := c.do(req, &resp); err != nil {
		return "", fmt.Errorf("get zone %q: %w", zoneName, err)
	}
	for _, z := range resp.Zones {
		if strings.TrimSuffix(z.Name, ".") == strings.TrimSuffix(zoneName, ".") {
			return string(z.ID), nil
		}
	}
	return "", fmt.Errorf("zone %q not found", zoneName)
}

func (c *Client) UpsertRRSet(zoneID string, rrset core.DNSRRSet) error {
	name := c.toRRSetName(rrset.Name)
	typ := strings.ToUpper(strings.TrimSpace(rrset.Type))
	values := normalizeValues(rrset.Values)
	if typ == "" || name == "" || len(values) == 0 {
		return fmt.Errorf("invalid rrset")
	}

	// If it exists, overwrite records via set_records action (idempotent).
	existing, err := c.GetRRSet(zoneID, rrset.Name, typ)
	if err != nil {
		return err
	}
	if existing != nil {
		return c.setRecords(zoneID, name, typ, values)
	}

	// Create new RRSet.
	var recs []apiRRSetRecord
	for _, v := range values {
		recs = append(recs, apiRRSetRecord{Value: v})
	}
	payload, _ := json.Marshal(createRRSetRequest{
		Name:    name,
		Type:    typ,
		TTL:     rrset.TTL,
		Records: recs,
	})
	req, err := c.newRequest(http.MethodPost, fmt.Sprintf("/zones/%s/rrsets", zoneID), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, nil)
}

func (c *Client) DeleteRRSet(zoneID string, name string, typ string) error {
	typ = strings.ToUpper(strings.TrimSpace(typ))
	existing, err := c.GetRRSet(zoneID, name, typ)
	if err != nil {
		return err
	}
	if existing == nil || len(existing.Values) == 0 {
		return nil
	}
	rrName := c.toRRSetName(name)
	return c.removeRecords(zoneID, rrName, typ, normalizeValues(existing.Values))
}

func (c *Client) GetRRSet(zoneID string, name string, typ string) (*core.DNSRRSet, error) {
	rrName := c.toRRSetName(name)
	typ = strings.ToUpper(strings.TrimSpace(typ))
	req, err := c.newRequest(http.MethodGet, fmt.Sprintf("/zones/%s/rrsets/%s/%s", zoneID, rrName, typ), nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		RRSet apiRRSet `json:"rrset"`
	}
	if err := c.do(req, &resp); err != nil {
		// Not found should be treated as nil.
		if strings.Contains(err.Error(), "404") || strings.Contains(strings.ToLower(err.Error()), "not found") {
			return nil, nil
		}
		return nil, err
	}
	var values []string
	for _, r := range resp.RRSet.Records {
		values = append(values, r.Value)
	}
	return &core.DNSRRSet{
		Type:   resp.RRSet.Type,
		Name:   c.fromRRSetName(resp.RRSet.Name),
		TTL:    resp.RRSet.TTL,
		Values: values,
	}, nil
}

func (c *Client) setRecords(zoneID, rrName, typ string, values []string) error {
	var recs []apiRRSetRecord
	for _, v := range values {
		recs = append(recs, apiRRSetRecord{Value: v})
	}
	payload, _ := json.Marshal(rrsetActionRequest{Records: recs})
	req, err := c.newRequest(http.MethodPost, fmt.Sprintf("/zones/%s/rrsets/%s/%s/actions/set_records", zoneID, rrName, typ), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, nil)
}

func (c *Client) removeRecords(zoneID, rrName, typ string, values []string) error {
	var recs []apiRRSetRecord
	for _, v := range values {
		recs = append(recs, apiRRSetRecord{Value: v})
	}
	payload, _ := json.Marshal(rrsetActionRequest{Records: recs})
	req, err := c.newRequest(http.MethodPost, fmt.Sprintf("/zones/%s/rrsets/%s/%s/actions/remove_records", zoneID, rrName, typ), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, nil)
}

func normalizeValues(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func (c *Client) toRRSetName(name string) string {
	n := strings.TrimSuffix(strings.TrimSpace(name), ".")
	zone := strings.TrimSuffix(c.ZoneName, ".")

	if n == zone || n == "@" || n == "" {
		return "@"
	}
	if strings.HasSuffix(n, "."+zone) {
		n = strings.TrimSuffix(n, "."+zone)
	}
	// Hetzner requires rrset name to be lower case and not include the zone suffix.
	return strings.ToLower(n)
}

func (c *Client) fromRRSetName(rrName string) string {
	rrName = strings.TrimSpace(rrName)
	if rrName == "@" || rrName == "" {
		return c.ZoneName
	}
	return rrName + "." + c.ZoneName
}

func (c *Client) newRequest(method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, c.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIToken)
	return req, nil
}

func (c *Client) do(req *http.Request, out interface{}) error {
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr apiError
		_ = json.Unmarshal(b, &apiErr)
		msg := strings.TrimSpace(apiErr.Error.Message)
		if msg == "" {
			msg = string(b)
		}
		return fmt.Errorf("hetzner cloud api %d: %s", resp.StatusCode, msg)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
