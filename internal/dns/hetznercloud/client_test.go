package hetznercloud

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sisumail/sisumail/internal/core"
)

type mockCloud struct {
	mu    sync.Mutex
	token string
	zones []apiZone
	// key: zoneID|name|type
	rrsets map[string]apiRRSet
}

func newMockCloud(token string) *mockCloud {
	return &mockCloud{
		token:  token,
		zones:  []apiZone{{ID: "z1", Name: "sisumail.fi"}},
		rrsets: map[string]apiRRSet{
			// empty
		},
	}
}

func (m *mockCloud) key(zoneID, name, typ string) string {
	return zoneID + "|" + name + "|" + typ
}

func (m *mockCloud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+m.token {
		http.Error(w, `{"error":{"message":"Invalid authentication credentials"}}`, http.StatusUnauthorized)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/zones") && r.URL.Path == "/zones":
		name := r.URL.Query().Get("name")
		var out []apiZone
		for _, z := range m.zones {
			if name == "" || z.Name == name {
				out = append(out, z)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"zones": out})
		return

	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/rrsets/"):
		parts := strings.Split(r.URL.Path, "/")
		// /zones/{zid}/rrsets/{name}/{type}
		if len(parts) != 6 {
			http.NotFound(w, r)
			return
		}
		zid := parts[2]
		name := parts[4]
		typ := parts[5]
		rr, ok := m.rrsets[m.key(zid, name, typ)]
		if !ok {
			http.Error(w, `{"error":{"message":"not found"}}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rrset": rr})
		return

	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rrsets"):
		parts := strings.Split(r.URL.Path, "/")
		// /zones/{zid}/rrsets
		zid := parts[2]
		var req createRRSetRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":{"message":"bad request"}}`, http.StatusBadRequest)
			return
		}
		rr := apiRRSet{
			Name:    req.Name,
			Type:    req.Type,
			TTL:     req.TTL,
			Records: req.Records,
		}
		k := m.key(zid, rr.Name, rr.Type)
		m.rrsets[k] = rr
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"rrset": rr})
		return

	case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/actions/set_records"):
		parts := strings.Split(r.URL.Path, "/")
		// /zones/{zid}/rrsets/{name}/{type}/actions/set_records
		zid := parts[2]
		name := parts[4]
		typ := parts[5]
		var req rrsetActionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":{"message":"bad request"}}`, http.StatusBadRequest)
			return
		}
		k := m.key(zid, name, typ)
		rr, ok := m.rrsets[k]
		if !ok {
			http.Error(w, `{"error":{"message":"not found"}}`, http.StatusNotFound)
			return
		}
		rr.Records = req.Records
		m.rrsets[k] = rr
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"rrset": rr})
		return

	case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/actions/remove_records"):
		parts := strings.Split(r.URL.Path, "/")
		// /zones/{zid}/rrsets/{name}/{type}/actions/remove_records
		zid := parts[2]
		name := parts[4]
		typ := parts[5]
		var req rrsetActionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":{"message":"bad request"}}`, http.StatusBadRequest)
			return
		}
		k := m.key(zid, name, typ)
		rr, ok := m.rrsets[k]
		if !ok {
			w.WriteHeader(http.StatusOK)
			return
		}
		// naive remove: if all values match, delete rrset.
		if len(req.Records) == len(rr.Records) {
			delete(m.rrsets, k)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	http.NotFound(w, r)
}

func TestZonesAndRRSetLifecycle(t *testing.T) {
	mock := newMockCloud("tok")
	srv := httptest.NewServer(mock)
	defer srv.Close()

	c := NewClient("tok", "sisumail.fi")
	c.BaseURL = srv.URL
	c.HTTPClient = srv.Client()

	zid, err := c.GetZoneIDByName("sisumail.fi")
	if err != nil {
		t.Fatalf("GetZoneIDByName: %v", err)
	}
	if zid != "z1" {
		t.Fatalf("expected z1, got %s", zid)
	}

	rr := core.DNSRRSet{
		Type:   "MX",
		Name:   "niklas.sisumail.fi",
		TTL:    300,
		Values: []string{"10 niklas.v6.sisumail.fi.", "20 spool.sisumail.fi."},
	}
	if err := c.UpsertRRSet(zid, rr); err != nil {
		t.Fatalf("UpsertRRSet create: %v", err)
	}
	got, err := c.GetRRSet(zid, "niklas.sisumail.fi", "MX")
	if err != nil || got == nil || len(got.Values) != 2 {
		t.Fatalf("GetRRSet: got=%+v err=%v", got, err)
	}

	// overwrite (set_records path)
	rr.Values = []string{"10 niklas.v6.sisumail.fi.", "20 spool.sisumail.fi.", "30 backup.example."}
	if err := c.UpsertRRSet(zid, rr); err != nil {
		t.Fatalf("UpsertRRSet update: %v", err)
	}

	if err := c.DeleteRRSet(zid, "niklas.sisumail.fi", "MX"); err != nil {
		t.Fatalf("DeleteRRSet: %v", err)
	}
	none, err := c.GetRRSet(zid, "niklas.sisumail.fi", "MX")
	if err != nil {
		t.Fatalf("GetRRSet after delete: %v", err)
	}
	if none != nil {
		t.Fatalf("expected nil rrset after delete, got %+v", none)
	}
}

func TestUnauthorized(t *testing.T) {
	mock := newMockCloud("tok")
	srv := httptest.NewServer(mock)
	defer srv.Close()

	c := NewClient("wrong", "sisumail.fi")
	c.BaseURL = srv.URL
	c.HTTPClient = srv.Client()

	_, err := c.GetZoneIDByName("sisumail.fi")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "401") && !strings.Contains(strings.ToLower(err.Error()), "invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}
