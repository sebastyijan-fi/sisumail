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
}

func (r *DomainKeyResolver) Resolve(domain string) (string, error) {
	if r.Store == nil {
		return "", fmt.Errorf("missing store")
	}
	if r.Zone == "" {
		return "", fmt.Errorf("missing zone")
	}

	suffix := "." + r.Zone
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
	return rec.PubKeyText, nil
}

