package identity

import (
	"fmt"
	"regexp"
	"strings"
)

// usernameDNSLabel matches a single DNS label as required by v1.
// - lowercase only (we canonicalize input to lowercase)
// - 1..63 chars
// - letters/digits/hyphen
// - MUST NOT start or end with '-'
var usernameDNSLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// CanonicalUsername returns the normalized username used as the identity key.
//
// v1 usernames are a single DNS label. That keeps:
// - user@<zone> working cleanly
// - <user>.v6.<zone> workable without punycode/unicode edge cases
func CanonicalUsername(u string) (string, error) {
	u = strings.ToLower(strings.TrimSpace(u))
	if u == "" {
		return "", fmt.Errorf("missing username")
	}
	if len(u) > 63 {
		return "", fmt.Errorf("username too long")
	}
	if !usernameDNSLabel.MatchString(u) {
		return "", fmt.Errorf("invalid username")
	}
	return u, nil
}
