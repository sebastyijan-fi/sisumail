package main

import (
	"strings"
	"testing"
	"time"

	"github.com/sisumail/sisumail/internal/core"
	"github.com/sisumail/sisumail/internal/proto"
)

func TestInjectSisumailHeaders(t *testing.T) {
	in := []byte("From: a@example.com\r\nSubject: hello\r\n\r\nbody\r\n")
	out := injectSisumailHeaders(in, map[string]string{
		"X-Sisumail-Tier": "tier1",
	})
	s := string(out)
	if !strings.Contains(s, "X-Sisumail-Tier: tier1\r\n\r\nbody") {
		t.Fatalf("expected injected header, got: %q", s)
	}
}

func TestDeliveryMetaBridgeTakeOnce(t *testing.T) {
	b := newDeliveryMetaBridge()
	meta := proto.SMTPDeliveryMeta{
		SenderPort: 25,
		ReceivedAt: time.Now(),
	}
	b.Put("127.0.0.1:1234", meta)

	got, ok := b.Take("127.0.0.1:1234")
	if !ok {
		t.Fatal("expected metadata")
	}
	if got.SenderPort != 25 {
		t.Fatalf("unexpected sender port: %d", got.SenderPort)
	}
	if _, ok := b.Take("127.0.0.1:1234"); ok {
		t.Fatal("expected one-shot metadata consumption")
	}
}

func TestTierBadge(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "tier1", want: "Tier1 Blind"},
		{in: "tier2", want: "Tier2 Spool"},
		{in: "", want: "Unknown"},
		{in: "custom", want: "custom"},
	}
	for _, tc := range cases {
		if got := tierBadge(tc.in); got != tc.want {
			t.Fatalf("tierBadge(%q): got %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestApplyInboxFilter(t *testing.T) {
	entries := []core.MaildirEntry{
		{ID: "1", Tier: "tier1", Seen: false},
		{ID: "2", Tier: "tier2", Seen: false},
		{ID: "3", Tier: "tier1", Seen: true},
	}

	if got := applyInboxFilter(entries, inboxFilterAll); len(got) != 3 {
		t.Fatalf("all: got %d, want 3", len(got))
	}
	if got := applyInboxFilter(entries, inboxFilterTier1); len(got) != 2 {
		t.Fatalf("tier1: got %d, want 2", len(got))
	}
	if got := applyInboxFilter(entries, inboxFilterTier2); len(got) != 1 {
		t.Fatalf("tier2: got %d, want 1", len(got))
	}
	if got := applyInboxFilter(entries, inboxFilterUnread); len(got) != 2 {
		t.Fatalf("unread: got %d, want 2", len(got))
	}
}
