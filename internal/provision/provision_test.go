package provision

import (
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/sisumail/sisumail/internal/core"
)

// mockDNS is an in-memory core.DNSProvider for testing.
type mockDNS struct {
	mu      sync.Mutex
	zones   map[string]string                         // name -> id
	records map[string]map[string]core.DNSRecordEntry // zoneID -> recID -> entry
	nextID  int
}

func newMockDNS() *mockDNS {
	return &mockDNS{
		zones: map[string]string{
			"sisumail.fi": "zone-1",
		},
		records: make(map[string]map[string]core.DNSRecordEntry),
	}
}

func (m *mockDNS) GetZoneIDByName(name string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.zones[name]
	if !ok {
		return "", fmt.Errorf("zone not found: %s", name)
	}
	return id, nil
}

func (m *mockDNS) CreateRecord(zoneID string, rec core.DNSRecord) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	id := fmt.Sprintf("rec-%d", m.nextID)
	if m.records[zoneID] == nil {
		m.records[zoneID] = make(map[string]core.DNSRecordEntry)
	}
	m.records[zoneID][id] = core.DNSRecordEntry{
		ID:    id,
		Type:  rec.Type,
		Name:  rec.Name,
		Value: rec.Value,
		TTL:   rec.TTL,
	}
	return id, nil
}

func (m *mockDNS) DeleteRecord(zoneID, recordID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.records[zoneID][recordID]; !ok {
		return fmt.Errorf("record not found: %s", recordID)
	}
	delete(m.records[zoneID], recordID)
	return nil
}

func (m *mockDNS) ListRecords(zoneID, name string) ([]core.DNSRecordEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []core.DNSRecordEntry
	for _, r := range m.records[zoneID] {
		if name == "" || r.Name == name {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *mockDNS) allRecords(zoneID string) []core.DNSRecordEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []core.DNSRecordEntry
	for _, r := range m.records[zoneID] {
		out = append(out, r)
	}
	return out
}

func TestProvisionCreatesExactRecordSet(t *testing.T) {
	dns := newMockDNS()
	prov := &Provisioner{
		DNS:      dns,
		ZoneName: "sisumail.fi",
	}

	ipv6 := net.ParseIP("2a01:4f8:1234::42")
	if err := prov.ProvisionUser("niklas", ipv6); err != nil {
		t.Fatalf("ProvisionUser: %v", err)
	}

	records := dns.allRecords("zone-1")
	if len(records) != 5 {
		t.Fatalf("expected 5 records, got %d", len(records))
	}

	// Build a map by type+name for easier assertions.
	type key struct{ typ, name string }
	byKey := make(map[key]string)
	for _, r := range records {
		byKey[key{r.Type, r.Name}] = r.Value
	}

	checks := []struct {
		typ, name, wantValue string
	}{
		{"MX", "niklas.sisumail.fi", "10 v6.niklas.sisumail.fi."},
		{"MX", "niklas.sisumail.fi", "20 spool.sisumail.fi."},
		{"AAAA", "v6.niklas.sisumail.fi", "2a01:4f8:1234::42"},
		{"TXT", "niklas.sisumail.fi", "v=spf1 -all"},
		{"CAA", "niklas.sisumail.fi", `0 issue "letsencrypt.org"`},
	}

	// Count MX records separately since they share the same key.
	mxCount := 0
	for _, r := range records {
		if r.Type == "MX" && r.Name == "niklas.sisumail.fi" {
			mxCount++
			if r.Value != "10 v6.niklas.sisumail.fi." && r.Value != "20 spool.sisumail.fi." {
				t.Errorf("unexpected MX value: %s", r.Value)
			}
		}
	}
	if mxCount != 2 {
		t.Errorf("expected 2 MX records, got %d", mxCount)
	}

	// Check non-MX records.
	for _, c := range checks {
		if c.typ == "MX" {
			continue
		}
		v, ok := byKey[key{c.typ, c.name}]
		if !ok {
			t.Errorf("missing %s %s", c.typ, c.name)
			continue
		}
		if v != c.wantValue {
			t.Errorf("%s %s: got %q, want %q", c.typ, c.name, v, c.wantValue)
		}
	}
}

func TestDeprovisionRemovesAllRecords(t *testing.T) {
	dns := newMockDNS()
	prov := &Provisioner{
		DNS:      dns,
		ZoneName: "sisumail.fi",
	}

	ipv6 := net.ParseIP("2a01:4f8:1234::42")
	if err := prov.ProvisionUser("niklas", ipv6); err != nil {
		t.Fatalf("ProvisionUser: %v", err)
	}
	if len(dns.allRecords("zone-1")) != 5 {
		t.Fatal("expected 5 records before deprovision")
	}

	if err := prov.DeprovisionUser("niklas"); err != nil {
		t.Fatalf("DeprovisionUser: %v", err)
	}
	if len(dns.allRecords("zone-1")) != 0 {
		t.Fatalf("expected 0 records after deprovision, got %d", len(dns.allRecords("zone-1")))
	}
}

func TestProvisionIdempotentZoneLookup(t *testing.T) {
	dns := newMockDNS()
	prov := &Provisioner{
		DNS:      dns,
		ZoneName: "sisumail.fi",
	}

	ipv6 := net.ParseIP("::1")

	// Provision twice; zone ID should be cached after first call.
	if err := prov.ProvisionUser("alice", ipv6); err != nil {
		t.Fatalf("first provision: %v", err)
	}
	_ = prov.DeprovisionUser("alice")
	if err := prov.ProvisionUser("alice", ipv6); err != nil {
		t.Fatalf("second provision: %v", err)
	}
}
