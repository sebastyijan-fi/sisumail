package main

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sisumail/sisumail/internal/core"
)

type acmeDNS01Controller struct {
	zone string
	dns  core.DNSProvider

	mu     sync.Mutex
	byUser map[string]rateWindow
	perMin int
}

func newACMEDNS01Controller(zone string, dns core.DNSProvider, perMin int) *acmeDNS01Controller {
	return &acmeDNS01Controller{
		zone:   strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), "."),
		dns:    dns,
		byUser: make(map[string]rateWindow),
		perMin: perMin,
	}
}

func (c *acmeDNS01Controller) enabled() bool {
	return c != nil && c.dns != nil && c.zone != ""
}

func (c *acmeDNS01Controller) allowUser(user string) bool {
	if c == nil || c.perMin <= 0 {
		return true
	}
	user = strings.ToLower(strings.TrimSpace(user))
	if user == "" {
		user = "unknown"
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	w, ok := c.byUser[user]
	if !ok || now.Sub(w.start) >= time.Minute {
		c.byUser[user] = rateWindow{start: now, count: 1}
		return true
	}
	if w.count >= c.perMin {
		return false
	}
	w.count++
	c.byUser[user] = w
	return true
}

func (c *acmeDNS01Controller) ensureAuthorizedHost(user, host string) error {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	want := fmt.Sprintf("v6.%s.%s", strings.ToLower(strings.TrimSpace(user)), c.zone)
	if host != want {
		return fmt.Errorf("unauthorized hostname")
	}
	return nil
}

func (c *acmeDNS01Controller) present(user, host, value string) error {
	if !c.enabled() {
		return fmt.Errorf("acme dns control unavailable")
	}
	if !c.allowUser(user) {
		return fmt.Errorf("rate limited")
	}
	if err := c.ensureAuthorizedHost(user, host); err != nil {
		return err
	}
	zoneID, err := c.dns.GetZoneIDByName(c.zone)
	if err != nil {
		return err
	}
	fqdn := "_acme-challenge." + strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	v := quoteTXT(value)
	existing, err := c.dns.GetRRSet(zoneID, fqdn, "TXT")
	if err != nil {
		return err
	}
	values := []string{v}
	if existing != nil {
		values = mergeTXTValues(existing.Values, v)
	}
	return c.dns.UpsertRRSet(zoneID, core.DNSRRSet{
		Type:   "TXT",
		Name:   fqdn,
		TTL:    60,
		Values: values,
	})
}

func (c *acmeDNS01Controller) cleanup(user, host, value string) error {
	if !c.enabled() {
		return fmt.Errorf("acme dns control unavailable")
	}
	if !c.allowUser(user) {
		return fmt.Errorf("rate limited")
	}
	if err := c.ensureAuthorizedHost(user, host); err != nil {
		return err
	}
	zoneID, err := c.dns.GetZoneIDByName(c.zone)
	if err != nil {
		return err
	}
	fqdn := "_acme-challenge." + strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	existing, err := c.dns.GetRRSet(zoneID, fqdn, "TXT")
	if err != nil || existing == nil {
		return err
	}
	rest := removeTXTValue(existing.Values, value)
	if len(rest) == 0 {
		return c.dns.DeleteRRSet(zoneID, fqdn, "TXT")
	}
	return c.dns.UpsertRRSet(zoneID, core.DNSRRSet{
		Type:   "TXT",
		Name:   fqdn,
		TTL:    existing.TTL,
		Values: rest,
	})
}

func quoteTXT(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "\"") && strings.HasSuffix(v, "\"") {
		return v
	}
	return `"` + v + `"`
}

func normalizeTXT(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, `"`)
	v = strings.TrimSuffix(v, `"`)
	return v
}

func mergeTXTValues(existing []string, add string) []string {
	addNorm := normalizeTXT(add)
	out := make([]string, 0, len(existing)+1)
	seen := map[string]bool{}
	for _, v := range existing {
		n := normalizeTXT(v)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, quoteTXT(n))
	}
	if !seen[addNorm] && addNorm != "" {
		out = append(out, quoteTXT(addNorm))
	}
	return out
}

func removeTXTValue(existing []string, remove string) []string {
	rm := normalizeTXT(remove)
	var out []string
	for _, v := range existing {
		n := normalizeTXT(v)
		if n == "" || n == rm {
			continue
		}
		out = append(out, quoteTXT(n))
	}
	return out
}
