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

	records := []core.DNSRecord{
		{Type: "MX", Name: userDomain, Value: fmt.Sprintf("10 %s.", tier1Host), TTL: 300},
		{Type: "MX", Name: userDomain, Value: fmt.Sprintf("20 spool.%s.", p.ZoneName), TTL: 300},
		{Type: "AAAA", Name: tier1Host, Value: destIPv6.String(), TTL: 300},
		{Type: "TXT", Name: userDomain, Value: "v=spf1 -all", TTL: 3600},
		{Type: "CAA", Name: userDomain, Value: `0 issue "letsencrypt.org"`, TTL: 3600},
	}

	for _, rec := range records {
		if err := p.ensureRecord(zoneID, rec); err != nil {
			// Best effort: try to clean up already-created records on failure.
			_ = p.DeprovisionUser(username)
			return fmt.Errorf("provision %s: ensure %s %s: %w", username, rec.Type, rec.Name, err)
		}
	}
	return nil
}

func (p *Provisioner) ensureRecord(zoneID string, rec core.DNSRecord) error {
	// Idempotency: if record already exists with the same name/type/value, do nothing.
	existing, err := p.DNS.ListRecords(zoneID, rec.Name)
	if err != nil {
		return err
	}
	for _, e := range existing {
		if e.Name == rec.Name && e.Type == rec.Type && e.Value == rec.Value {
			return nil
		}
	}
	_, err = p.DNS.CreateRecord(zoneID, rec)
	return err
}

// DeprovisionUser removes all DNS records for a user.
func (p *Provisioner) DeprovisionUser(username string) error {
	zoneID, err := p.getZoneID()
	if err != nil {
		return err
	}

	userDomain := fmt.Sprintf("%s.%s", username, p.ZoneName)
	tier1Host := fmt.Sprintf("v6.%s.%s", username, p.ZoneName)

	// Delete records matching both the user domain and the Tier 1 hostname.
	for _, name := range []string{userDomain, tier1Host} {
		records, err := p.DNS.ListRecords(zoneID, name)
		if err != nil {
			return fmt.Errorf("deprovision %s: list %s: %w", username, name, err)
		}
		for _, rec := range records {
			if err := p.DNS.DeleteRecord(zoneID, rec.ID); err != nil {
				return fmt.Errorf("deprovision %s: delete %s (%s): %w", username, rec.ID, rec.Type, err)
			}
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
