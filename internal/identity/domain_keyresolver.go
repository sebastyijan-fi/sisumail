package identity

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// DomainKeyResolver implements core.KeyResolver using the identity Store.
//
// It maps "<user>.<zone>" to the user's SSH public key stored in SQLite.
// Usernames are restricted to a single DNS label (no dots) in v1.
type DomainKeyResolver struct {
	Store   *Store
	Zone    string
	Timeout time.Duration

	// AllowTier2Gate enforces per-user opt-in for Tier 2 compatibility ingest.
	// When true, Resolve rejects recipients whose identity record has AllowTier2=false.
	AllowTier2Gate bool
}

func (r *DomainKeyResolver) Resolve(domain string) (string, error) {
	if r.Store == nil {
		return "", fmt.Errorf("missing store")
	}
	if r.Zone == "" {
		return "", fmt.Errorf("missing zone")
	}

	domain = strings.ToLower(strings.TrimSpace(domain))
	zone := strings.ToLower(strings.TrimSpace(r.Zone))
	suffix := "." + zone
	if !strings.HasSuffix(domain, suffix) {
		return "", fmt.Errorf("domain not in zone")
	}
	user := strings.TrimSuffix(domain, suffix)
	if user == "" || strings.Contains(user, ".") {
		return "", fmt.Errorf("invalid user domain")
	}

	ctx := context.Background()
	if r.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}

	rec, err := r.Store.GetByUsername(ctx, user)
	if err != nil {
		return "", err
	}
	if rec == nil {
		return "", fmt.Errorf("unknown recipient")
	}
	if r.AllowTier2Gate && !rec.AllowTier2 {
		return "", fmt.Errorf("tier2 disabled for recipient")
	}
	return rec.PubKeyText, nil
}
