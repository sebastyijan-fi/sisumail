package tier2

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseDenylist(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "denylist.txt")
	content := "# comment\n\n192.0.2.10\n2001:db8::/64\n198.51.100.0/24\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	nets, err := ParseDenylist(p)
	if err != nil {
		t.Fatalf("ParseDenylist: %v", err)
	}
	if len(nets) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(nets))
	}

	g := NewSourceGuard(10, 10, nets)
	if !g.IsDenied(net.ParseIP("192.0.2.10")) {
		t.Fatal("expected single IPv4 denylist match")
	}
	if !g.IsDenied(net.ParseIP("2001:db8::1234")) {
		t.Fatal("expected IPv6 CIDR denylist match")
	}
	if g.IsDenied(net.ParseIP("203.0.113.10")) {
		t.Fatal("unexpected denylist match")
	}
}

func TestSourceGuardConnAcquireRelease(t *testing.T) {
	g := NewSourceGuard(1, 10, nil)
	if !g.TryAcquireConn("198.51.100.10") {
		t.Fatal("expected first acquire to pass")
	}
	if g.TryAcquireConn("198.51.100.10") {
		t.Fatal("expected second acquire to be blocked")
	}
	g.ReleaseConn("198.51.100.10")
	if !g.TryAcquireConn("198.51.100.10") {
		t.Fatal("expected acquire to pass after release")
	}
}

func TestSourceGuardMessageRateLimit(t *testing.T) {
	g := NewSourceGuard(10, 2, nil)
	now := time.Now()
	g.nowFn = func() time.Time { return now }

	if !g.AllowMessage("203.0.113.5") {
		t.Fatal("expected first message")
	}
	if !g.AllowMessage("203.0.113.5") {
		t.Fatal("expected second message")
	}
	if g.AllowMessage("203.0.113.5") {
		t.Fatal("expected third message to be rate-limited")
	}

	now = now.Add(61 * time.Second)
	if !g.AllowMessage("203.0.113.5") {
		t.Fatal("expected allowance after window reset")
	}
}
