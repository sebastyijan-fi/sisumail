package main

import (
	"bufio"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

func TestParseRecipient(t *testing.T) {
	u, a, err := parseRecipient("<alice@sisumail.fi>", "sisumail.fi")
	if err != nil {
		t.Fatalf("parse root recipient: %v", err)
	}
	if u != "alice" || a != "alice@sisumail.fi" {
		t.Fatalf("unexpected root parse u=%q a=%q", u, a)
	}

	u, a, err = parseRecipient("<steam@alice.sisumail.fi>", "sisumail.fi")
	if err != nil {
		t.Fatalf("parse alias recipient: %v", err)
	}
	if u != "alice" || a != "steam@alice.sisumail.fi" {
		t.Fatalf("unexpected alias parse u=%q a=%q", u, a)
	}

	if _, _, err := parseRecipient("<steam@example.com>", "sisumail.fi"); err == nil {
		t.Fatal("expected invalid host rejection")
	}
}

func TestCiphertextPayloadPolicy(t *testing.T) {
	if isCiphertextPayload("hello world") {
		t.Fatal("expected plaintext rejection")
	}
	if !isCiphertextPayload("ciphertext:abcd") {
		t.Fatal("expected ciphertext prefix accept")
	}
	if !isCiphertextPayload("age1qxy...") {
		t.Fatal("expected age payload accept")
	}
}

func TestAllowIPRateLimit(t *testing.T) {
	s := &smtpIngress{perIPPerMinute: 2, ipHits: map[string][]time.Time{}}
	now := time.Now()
	if !s.allowIP("1.2.3.4", now) {
		t.Fatal("first call should pass")
	}
	if !s.allowIP("1.2.3.4", now.Add(10*time.Second)) {
		t.Fatal("second call should pass")
	}
	if s.allowIP("1.2.3.4", now.Add(20*time.Second)) {
		t.Fatal("third call should be rate limited")
	}
	if !s.allowIP("1.2.3.4", now.Add(61*time.Second)) {
		t.Fatal("window should have rolled over")
	}
}

func TestReadSMTPDataLimit(t *testing.T) {
	r := strings.NewReader("line1\r\nline2\r\n.\r\n")
	tp := textproto.NewReader(bufio.NewReader(r))
	out, err := readSMTPData(tp, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "line1") {
		t.Fatalf("unexpected output: %q", out)
	}

	r2 := strings.NewReader("1234567890\r\n.\r\n")
	tp2 := textproto.NewReader(bufio.NewReader(r2))
	if _, err := readSMTPData(tp2, 5); err == nil {
		t.Fatal("expected size error")
	}
}
