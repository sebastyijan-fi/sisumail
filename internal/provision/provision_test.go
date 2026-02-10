package provision

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/sisumail/sisumail/internal/core"
)

// mockDNSRR is an in-memory core.DNSProvider (RRSet-based) for testing.
type mockDNSRR struct {
	mu    sync.Mutex
	zones map[string]string // name -> id
	// key: zoneID|name|type
	rrsets map[string]core.DNSRRSet
}

func newMockDNSRR() *mockDNSRR {
	return &mockDNSRR{
		zones: map[string]string{
			"sisumail.fi": "zone-1",
		},
		rrsets: make(map[string]core.DNSRRSet),
	}
}

func (m *mockDNSRR) key(zoneID, name, typ string) string {
	return zoneID + "|" + name + "|" + strings.ToUpper(typ)
}

func (m *mockDNSRR) GetZoneIDByName(name string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.zones[name]
	if !ok {
		return "", fmt.Errorf("zone not found: %s", name)
	}
	return id, nil
}

func (m *mockDNSRR) UpsertRRSet(zoneID string, rr core.DNSRRSet) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rr.Type = strings.ToUpper(rr.Type)
	rr.Values = append([]string(nil), rr.Values...)
	sort.Strings(rr.Values)
	m.rrsets[m.key(zoneID, rr.Name, rr.Type)] = rr
	return nil
}

func (m *mockDNSRR) DeleteRRSet(zoneID string, name string, typ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rrsets, m.key(zoneID, name, typ))
	return nil
}

func (m *mockDNSRR) GetRRSet(zoneID string, name string, typ string) (*core.DNSRRSet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rr, ok := m.rrsets[m.key(zoneID, name, typ)]
	if !ok {
		return nil, nil
	}
	cp := rr
	cp.Values = append([]string(nil), rr.Values...)
	return &cp, nil
}

func (m *mockDNSRR) all(zoneID string) []core.DNSRRSet {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []core.DNSRRSet
	for k, rr := range m.rrsets {
		if strings.HasPrefix(k, zoneID+"|") {
			out = append(out, rr)
		}
	}
	return out
}

func TestProvisionCreatesExpectedRRSets(t *testing.T) {
	dns := newMockDNSRR()
	prov := &Provisioner{DNS: dns, ZoneName: "sisumail.fi"}

	ipv6 := net.ParseIP("2a01:4f8:1234::42")
	if err := prov.ProvisionUser("niklas", ipv6); err != nil {
		t.Fatalf("ProvisionUser: %v", err)
	}

	rrs := dns.all("zone-1")
	if len(rrs) != 4 {
		t.Fatalf("expected 4 rrsets, got %d", len(rrs))
	}

	get := func(name, typ string) *core.DNSRRSet {
		rr, _ := dns.GetRRSet("zone-1", name, typ)
		return rr
	}

	mx := get("niklas.sisumail.fi", "MX")
	if mx == nil {
		t.Fatalf("missing MX rrset")
	}
	sort.Strings(mx.Values)
	wantMX := []string{"10 v6.niklas.sisumail.fi.", "20 spool.sisumail.fi."}
	if strings.Join(mx.Values, "|") != strings.Join(wantMX, "|") {
		t.Fatalf("MX values got=%v want=%v", mx.Values, wantMX)
	}

	aaaa := get("v6.niklas.sisumail.fi", "AAAA")
	if aaaa == nil || len(aaaa.Values) != 1 || aaaa.Values[0] != "2a01:4f8:1234::42" {
		t.Fatalf("AAAA got=%+v", aaaa)
	}

	txt := get("niklas.sisumail.fi", "TXT")
	if txt == nil || len(txt.Values) != 1 || txt.Values[0] != `"v=spf1 -all"` {
		t.Fatalf("TXT got=%+v", txt)
	}

	caa := get("niklas.sisumail.fi", "CAA")
	if caa == nil || len(caa.Values) != 1 || caa.Values[0] != `0 issue "letsencrypt.org"` {
		t.Fatalf("CAA got=%+v", caa)
	}
}

func TestDeprovisionRemovesManagedRRSets(t *testing.T) {
	dns := newMockDNSRR()
	prov := &Provisioner{DNS: dns, ZoneName: "sisumail.fi"}

	ipv6 := net.ParseIP("2a01:4f8:1234::42")
	if err := prov.ProvisionUser("niklas", ipv6); err != nil {
		t.Fatalf("ProvisionUser: %v", err)
	}
	if err := prov.DeprovisionUser("niklas"); err != nil {
		t.Fatalf("DeprovisionUser: %v", err)
	}
	if len(dns.all("zone-1")) != 0 {
		t.Fatalf("expected 0 rrsets after deprovision")
	}
}
