package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestCanonicalUsername(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"niklas", "niklas", false},
		{" Niklas ", "niklas", false},
		{"a", "a", false},
		{"a-", "", true},
		{"-a", "", true},
		{"a..b", "", true},
		{"", "", true},
	}
	for _, tc := range cases {
		got, err := CanonicalUsername(tc.in)
		if tc.wantErr && err == nil {
			t.Fatalf("CanonicalUsername(%q) expected error, got %q", tc.in, got)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("CanonicalUsername(%q) unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("CanonicalUsername(%q) got %q want %q", tc.in, got, tc.want)
		}
	}
}

func TestStoreClaim_RateLimits(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "relay.db")

	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}

	_, prefix, err := net.ParseCIDR("2001:db8::/64")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

	newPub := func() ssh.PublicKey {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		k, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatalf("NewPublicKey: %v", err)
		}
		return k
	}

	lim := ClaimLimits{
		PerSourcePerHour: 1,
		PerSourcePerDay:  0,
		GlobalPerHour:    0,
		GlobalPerDay:     0,
		RetentionDays:    7,
	}
	bucket := "v4:203.0.113.0/24"

	aliceKey := newPub()
	alice, isNew, err := s.Claim(ctx, "Alice", aliceKey, prefix, bucket, lim)
	if err != nil {
		t.Fatalf("Claim alice: %v", err)
	}
	if !isNew {
		t.Fatalf("Claim alice expected isNew=true")
	}
	if alice.Username != "alice" {
		t.Fatalf("Claim alice username got %q want %q", alice.Username, "alice")
	}

	// Existing claim should not be rate limited.
	_, isNew, err = s.Claim(ctx, "alice", aliceKey, prefix, bucket, lim)
	if err != nil {
		t.Fatalf("Claim existing alice: %v", err)
	}
	if isNew {
		t.Fatalf("Claim existing alice expected isNew=false")
	}

	// Second new name from same bucket should be blocked.
	_, _, err = s.Claim(ctx, "bob", newPub(), prefix, bucket, lim)
	if err == nil {
		t.Fatalf("Claim bob expected rate limit error")
	}
	if err != ErrClaimRateLimited {
		t.Fatalf("Claim bob expected ErrClaimRateLimited, got %v", err)
	}
}

func TestStoreClaim_GlobalLimit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "relay.db")

	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}

	_, prefix, err := net.ParseCIDR("2001:db8::/64")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

	newPub := func() ssh.PublicKey {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		k, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatalf("NewPublicKey: %v", err)
		}
		return k
	}

	lim := ClaimLimits{
		PerSourcePerHour: 0,
		PerSourcePerDay:  0,
		GlobalPerHour:    1,
		GlobalPerDay:     0,
		RetentionDays:    7,
	}

	_, _, err = s.Claim(ctx, "alice", newPub(), prefix, "v4:203.0.113.0/24", lim)
	if err != nil {
		t.Fatalf("Claim alice: %v", err)
	}
	_, _, err = s.Claim(ctx, "bob", newPub(), prefix, "v4:198.51.100.0/24", lim)
	if err == nil {
		t.Fatalf("Claim bob expected rate limit error")
	}
	if err != ErrClaimRateLimited {
		t.Fatalf("Claim bob expected ErrClaimRateLimited, got %v", err)
	}
}
