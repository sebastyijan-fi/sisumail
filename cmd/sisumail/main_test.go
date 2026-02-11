package main

import (
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/sisumail/sisumail/internal/core"
	"github.com/sisumail/sisumail/internal/proto"
	"github.com/sisumail/sisumail/internal/tlsboot"
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

func TestApplySearchRows(t *testing.T) {
	rows := []inboxRow{
		{Entry: core.MaildirEntry{ID: "id-1"}, From: "alice@example.com", Subject: "hello"},
		{Entry: core.MaildirEntry{ID: "id-2"}, From: "bob@example.com", Subject: "status"},
	}

	if got := applySearchRows(rows, "alice"); len(got) != 1 {
		t.Fatalf("search alice: got %d, want 1", len(got))
	}
	if got := applySearchRows(rows, "ID-2"); len(got) != 1 {
		t.Fatalf("search id-2: got %d, want 1", len(got))
	}
	if got := applySearchRows(rows, ""); len(got) != 2 {
		t.Fatalf("search empty: got %d, want 2", len(got))
	}
}

func TestPaginateRows(t *testing.T) {
	rows := make([]inboxRow, 0, 5)
	for i := 0; i < 5; i++ {
		rows = append(rows, inboxRow{Entry: core.MaildirEntry{ID: string(rune('a' + i))}})
	}

	page1, total := paginateRows(rows, 1, 2)
	if total != 3 || len(page1) != 2 {
		t.Fatalf("page1: total=%d len=%d", total, len(page1))
	}
	page3, total := paginateRows(rows, 3, 2)
	if total != 3 || len(page3) != 1 {
		t.Fatalf("page3: total=%d len=%d", total, len(page3))
	}
}

func TestTrustSummary(t *testing.T) {
	h1 := mail.Header{}
	h1["X-Sisumail-Sender-Ip"] = []string{"1.2.3.4"}
	h1["X-Sisumail-Received-At"] = []string{"2026-02-11T00:00:00Z"}
	if got := trustSummary("tier1", h1); got != "blind+meta" {
		t.Fatalf("tier1 meta: got %q", got)
	}

	h2 := mail.Header{}
	h2["X-Sisumail-Spool-Message-Id"] = []string{"abc"}
	h2["X-Sisumail-Spool-Size"] = []string{"123"}
	if got := trustSummary("tier2", h2); got != "spool+proof" {
		t.Fatalf("tier2 proof: got %q", got)
	}

	if got := trustSummary("tier1", nil); got != "blind+nometa" {
		t.Fatalf("tier1 none: got %q", got)
	}
	if got := trustSummary("tier2", nil); got != "spool+noproof" {
		t.Fatalf("tier2 none: got %q", got)
	}
}

func TestParseChatSendCommand(t *testing.T) {
	peer, msg, ok := parseChatSendCommand("c bob hello world")
	if !ok || peer != "bob" || msg != "hello world" {
		t.Fatalf("parse failed: ok=%v peer=%q msg=%q", ok, peer, msg)
	}
	if _, _, ok := parseChatSendCommand("c bob"); ok {
		t.Fatal("expected parse failure without message")
	}
	if _, _, ok := parseChatSendCommand("c "); ok {
		t.Fatal("expected parse failure with empty command")
	}
}

func TestTLSCertStateSetIfChanged(t *testing.T) {
	c1, err := tlsboot.SelfSigned([]string{"a.example"}, time.Hour)
	if err != nil {
		t.Fatalf("SelfSigned c1: %v", err)
	}
	c2, err := tlsboot.SelfSigned([]string{"b.example"}, time.Hour)
	if err != nil {
		t.Fatalf("SelfSigned c2: %v", err)
	}
	s := newTLSCertState(c1)
	if s.SetIfChanged(c1) {
		t.Fatal("expected unchanged certificate to be ignored")
	}
	if !s.SetIfChanged(c2) {
		t.Fatal("expected changed certificate to be accepted")
	}
	got := s.Get()
	if got == nil || len(got.Certificate) == 0 {
		t.Fatal("expected current certificate")
	}
}

func TestLoadHCloudTokenPrefersPrimaryVar(t *testing.T) {
	t.Setenv("HCLOUD_TOKEN", "primary")
	t.Setenv("HETZNER_CLOUD_TOKEN", "fallback")
	if got := loadHCloudToken(); got != "primary" {
		t.Fatalf("loadHCloudToken got %q, want primary", got)
	}
}
