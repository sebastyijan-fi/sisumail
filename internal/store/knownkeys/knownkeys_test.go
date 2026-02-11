package knownkeys

import (
	"path/filepath"
	"testing"
)

func TestCheckAndUpdate(t *testing.T) {
	s := &Store{Path: filepath.Join(t.TempDir(), "known_keys.json")}

	status, prev, err := s.CheckAndUpdate("bob", "SHA256:abc")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if status != "new" || prev != "" {
		t.Fatalf("first status=%q prev=%q", status, prev)
	}

	status, prev, err = s.CheckAndUpdate("bob", "SHA256:abc")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if status != "unchanged" || prev != "SHA256:abc" {
		t.Fatalf("second status=%q prev=%q", status, prev)
	}

	status, prev, err = s.CheckAndUpdate("bob", "SHA256:def")
	if err != nil {
		t.Fatalf("changed: %v", err)
	}
	if status != "changed" || prev != "SHA256:abc" {
		t.Fatalf("changed status=%q prev=%q", status, prev)
	}
}

