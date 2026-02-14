package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sisumail/sisumail/internal/core"
)

type fakeDNS struct {
	zoneID string
	zone   string
	rr     map[string]core.DNSRRSet
}

func newFakeDNS(zone string) *fakeDNS {
	return &fakeDNS{zoneID: "z1", zone: zone, rr: make(map[string]core.DNSRRSet)}
}

func (f *fakeDNS) key(name, typ string) string {
	return strings.ToLower(strings.TrimSpace(typ)) + "|" + strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

func (f *fakeDNS) UpsertRRSet(zoneID string, rrset core.DNSRRSet) error {
	if zoneID != f.zoneID {
		return fmt.Errorf("bad zone id")
	}
	f.rr[f.key(rrset.Name, rrset.Type)] = rrset
	return nil
}

func (f *fakeDNS) DeleteRRSet(zoneID string, name string, typ string) error {
	if zoneID != f.zoneID {
		return fmt.Errorf("bad zone id")
	}
	delete(f.rr, f.key(name, typ))
	return nil
}

func (f *fakeDNS) GetRRSet(zoneID string, name string, typ string) (*core.DNSRRSet, error) {
	if zoneID != f.zoneID {
		return nil, fmt.Errorf("bad zone id")
	}
	v, ok := f.rr[f.key(name, typ)]
	if !ok {
		return nil, nil
	}
	cp := v
	return &cp, nil
}

func (f *fakeDNS) GetZoneIDByName(zoneName string) (string, error) {
	if strings.TrimSuffix(zoneName, ".") != strings.TrimSuffix(f.zone, ".") {
		return "", fmt.Errorf("zone not found")
	}
	return f.zoneID, nil
}

func TestACMEDNS01ControllerPresentAndCleanup(t *testing.T) {
	dns := newFakeDNS("sisumail.fi")
	c := newACMEDNS01Controller("sisumail.fi", dns, 100)
	host := "alice.v6.sisumail.fi"
	if err := c.present("alice", host, "tok1"); err != nil {
		t.Fatalf("present: %v", err)
	}
	rr, err := dns.GetRRSet("z1", "_acme-challenge."+host, "TXT")
	if err != nil || rr == nil {
		t.Fatalf("missing rrset after present: %v", err)
	}
	if len(rr.Values) != 1 || rr.Values[0] != `"tok1"` {
		t.Fatalf("unexpected rrset values: %#v", rr.Values)
	}
	if err := c.cleanup("alice", host, "tok1"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	rr, err = dns.GetRRSet("z1", "_acme-challenge."+host, "TXT")
	if err != nil {
		t.Fatalf("get rrset after cleanup: %v", err)
	}
	if rr != nil {
		t.Fatalf("expected rrset deletion, got %#v", rr)
	}
}

func TestACMEDNS01ControllerRejectsWrongHost(t *testing.T) {
	dns := newFakeDNS("sisumail.fi")
	c := newACMEDNS01Controller("sisumail.fi", dns, 100)
	if err := c.present("alice", "bob.v6.sisumail.fi", "tok1"); err == nil {
		t.Fatal("expected unauthorized hostname error")
	}
}

func TestACMEDNS01ControllerRateLimit(t *testing.T) {
	dns := newFakeDNS("sisumail.fi")
	c := newACMEDNS01Controller("sisumail.fi", dns, 1)
	host := "alice.v6.sisumail.fi"
	if err := c.present("alice", host, "tok1"); err != nil {
		t.Fatalf("first present: %v", err)
	}
	if err := c.cleanup("alice", host, "tok1"); err == nil {
		t.Fatal("expected second op to hit rate limit")
	}
}

// Keep the compiler honest that fakeDNS satisfies interface.
var _ core.DNSProvider = (*fakeDNS)(nil)
