package hetzner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sisumail/sisumail/internal/core"
)

// mockHetzner is a minimal in-memory mock of the Hetzner DNS API.
type mockHetzner struct {
	mu      sync.Mutex
	zones   map[string]string               // name -> id
	records map[string]map[string]apiRecord // zoneID -> recordID -> record
	nextID  int
	token   string
}

func newMockHetzner(token string) *mockHetzner {
	return &mockHetzner{
		zones: map[string]string{
			"sisumail.fi": "zone-1",
		},
		records: make(map[string]map[string]apiRecord),
		token:   token,
	}
}

func (m *mockHetzner) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Auth-API-Token") != m.token {
		http.Error(w, `{"error":{"message":"unauthorized","code":401}}`, http.StatusUnauthorized)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/zones"):
		name := r.URL.Query().Get("name")
		var zones []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		for n, id := range m.zones {
			if name == "" || n == name {
				zones = append(zones, struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				}{id, n})
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"zones": zones})

	case r.Method == http.MethodPost && r.URL.Path == "/records":
		var req createRecordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":{"message":"bad request"}}`, http.StatusBadRequest)
			return
		}
		m.nextID++
		id := "rec-" + strings.Repeat("0", 3) + string(rune('0'+m.nextID))
		rec := apiRecord{
			ID:     id,
			Type:   req.Type,
			Name:   req.Name,
			Value:  req.Value,
			TTL:    req.TTL,
			ZoneID: req.ZoneID,
		}
		if m.records[req.ZoneID] == nil {
			m.records[req.ZoneID] = make(map[string]apiRecord)
		}
		m.records[req.ZoneID][id] = rec
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"record": rec})

	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/records/"):
		recID := strings.TrimPrefix(r.URL.Path, "/records/")
		for zid, recs := range m.records {
			if _, ok := recs[recID]; ok {
				delete(m.records[zid], recID)
				w.WriteHeader(http.StatusOK)
				return
			}
		}
		http.Error(w, `{"error":{"message":"not found"}}`, http.StatusNotFound)

	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/records"):
		zoneID := r.URL.Query().Get("zone_id")
		var recs []apiRecord
		for _, rec := range m.records[zoneID] {
			recs = append(recs, rec)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"records": recs})

	default:
		http.Error(w, `{"error":{"message":"not found"}}`, http.StatusNotFound)
	}
}

func TestGetZoneIDByName(t *testing.T) {
	mock := newMockHetzner("test-token")
	srv := httptest.NewServer(mock)
	defer srv.Close()

	c := &Client{
		BaseURL:    srv.URL,
		APIToken:   "test-token",
		HTTPClient: srv.Client(),
	}

	id, err := c.GetZoneIDByName("sisumail.fi")
	if err != nil {
		t.Fatalf("GetZoneIDByName: %v", err)
	}
	if id != "zone-1" {
		t.Fatalf("expected zone-1, got %s", id)
	}

	_, err = c.GetZoneIDByName("nonexistent.fi")
	if err == nil {
		t.Fatal("expected error for nonexistent zone")
	}
}

func TestCreateAndListRecords(t *testing.T) {
	mock := newMockHetzner("test-token")
	srv := httptest.NewServer(mock)
	defer srv.Close()

	c := &Client{
		BaseURL:    srv.URL,
		APIToken:   "test-token",
		HTTPClient: srv.Client(),
	}

	rec := core.DNSRecord{
		Type:  "AAAA",
		Name:  "v6.niklas.sisumail.fi",
		Value: "2a01:4f8:1234::1",
		TTL:   300,
	}
	recID, err := c.CreateRecord("zone-1", rec)
	if err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}
	if recID == "" {
		t.Fatal("empty record ID")
	}

	records, err := c.ListRecords("zone-1", "")
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Type != "AAAA" || records[0].Value != "2a01:4f8:1234::1" {
		t.Fatalf("unexpected record: %+v", records[0])
	}
}

func TestDeleteRecord(t *testing.T) {
	mock := newMockHetzner("test-token")
	srv := httptest.NewServer(mock)
	defer srv.Close()

	c := &Client{
		BaseURL:    srv.URL,
		APIToken:   "test-token",
		HTTPClient: srv.Client(),
	}

	recID, err := c.CreateRecord("zone-1", core.DNSRecord{
		Type:  "MX",
		Name:  "niklas.sisumail.fi",
		Value: "10 v6.niklas.sisumail.fi.",
	})
	if err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}

	if err := c.DeleteRecord("zone-1", recID); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}

	records, err := c.ListRecords("zone-1", "")
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected 0 records after delete, got %d", len(records))
	}
}

func TestUnauthorized(t *testing.T) {
	mock := newMockHetzner("correct-token")
	srv := httptest.NewServer(mock)
	defer srv.Close()

	c := &Client{
		BaseURL:    srv.URL,
		APIToken:   "wrong-token",
		HTTPClient: srv.Client(),
	}

	_, err := c.GetZoneIDByName("sisumail.fi")
	if err == nil {
		t.Fatal("expected auth error")
	}
	if !strings.Contains(err.Error(), "401") && !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("expected unauthorized error, got: %v", err)
	}
}

func TestListRecordsFilterByName(t *testing.T) {
	mock := newMockHetzner("test-token")
	srv := httptest.NewServer(mock)
	defer srv.Close()

	c := &Client{
		BaseURL:    srv.URL,
		APIToken:   "test-token",
		HTTPClient: srv.Client(),
	}

	c.CreateRecord("zone-1", core.DNSRecord{Type: "AAAA", Name: "v6.niklas.sisumail.fi", Value: "::1"})
	c.CreateRecord("zone-1", core.DNSRecord{Type: "MX", Name: "niklas.sisumail.fi", Value: "10 v6.niklas.sisumail.fi."})
	c.CreateRecord("zone-1", core.DNSRecord{Type: "AAAA", Name: "v6.other.sisumail.fi", Value: "::2"})

	filtered, err := c.ListRecords("zone-1", "v6.niklas.sisumail.fi")
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected 1 filtered record, got %d", len(filtered))
	}
}
