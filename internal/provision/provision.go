// Package provision implements user DNS lifecycle management.
//
// ProvisionUser creates the exact DNS record set from the whitepaper §7
// (Split MX Architecture). DeprovisionUser tears it down.
package provision

import (
	"fmt"
	"net"

	"github.com/sisumail/sisumail/internal/core"
)

// Provisioner implements core.DNSProvisioner using a core.DNSProvider backend.
type Provisioner struct {
	DNS      core.DNSProvider
	ZoneName string // e.g. "sisumail.fi"
	zoneID   string // cached after first lookup
}

// ProvisionUser creates the full DNS record set for a new user.
//
// Records created (per whitepaper §7):
//
//	MX    <u>.sisumail.fi  →  10 v6.<u>.sisumail.fi.       (Tier 1)
//	MX    <u>.sisumail.fi  →  20 spool.sisumail.fi.        (Tier 2 fallback)
//	AAAA  v6.<u>.sisumail.fi  →  <destIPv6>                (Tier 1 destination)
//	TXT   <u>.sisumail.fi  →  v=spf1 -all                  (receive-only SPF)
//	CAA   <u>.sisumail.fi  →  0 issue "letsencrypt.org"    (ACME CA restriction)
func (p *Provisioner) ProvisionUser(username string, destIPv6 net.IP) error {
	zoneID, err := p.getZoneID()
	if err != nil {
		return err
	}

	userDomain := fmt.Sprintf("%s.%s", username, p.ZoneName)
	tier1Host := fmt.Sprintf("v6.%s.%s", username, p.ZoneName)

	rrsets := []core.DNSRRSet{
		{
			Type:   "MX",
			Name:   userDomain,
			TTL:    300,
			Values: []string{fmt.Sprintf("10 %s.", tier1Host), fmt.Sprintf("20 spool.%s.", p.ZoneName)},
		},
		{Type: "AAAA", Name: tier1Host, TTL: 300, Values: []string{destIPv6.String()}},
		{Type: "TXT", Name: userDomain, TTL: 3600, Values: []string{"v=spf1 -all"}},
		{Type: "CAA", Name: userDomain, TTL: 3600, Values: []string{`0 issue "letsencrypt.org"`}},
	}

	for _, rr := range rrsets {
		if err := p.DNS.UpsertRRSet(zoneID, rr); err != nil {
			// Best effort: try to clean up already-created records on failure.
			_ = p.DeprovisionUser(username)
			return fmt.Errorf("provision %s: upsert %s %s: %w", username, rr.Type, rr.Name, err)
		}
	}
	return nil
}

// DeprovisionUser removes all DNS records for a user.
func (p *Provisioner) DeprovisionUser(username string) error {
	zoneID, err := p.getZoneID()
	if err != nil {
		return err
	}

	userDomain := fmt.Sprintf("%s.%s", username, p.ZoneName)
	tier1Host := fmt.Sprintf("v6.%s.%s", username, p.ZoneName)

	// Delete RRSets we manage for this user.
	for _, rr := range []struct {
		name string
		typ  string
	}{
		{name: userDomain, typ: "MX"},
		{name: tier1Host, typ: "AAAA"},
		{name: userDomain, typ: "TXT"},
		{name: userDomain, typ: "CAA"},
	} {
		if err := p.DNS.DeleteRRSet(zoneID, rr.name, rr.typ); err != nil {
			return fmt.Errorf("deprovision %s: delete rrset %s %s: %w", username, rr.typ, rr.name, err)
		}
	}
	return nil
}

func (p *Provisioner) getZoneID() (string, error) {
	if p.zoneID != "" {
		return p.zoneID, nil
	}
	id, err := p.DNS.GetZoneIDByName(p.ZoneName)
	if err != nil {
		return "", err
	}
	p.zoneID = id
	return id, nil
}
