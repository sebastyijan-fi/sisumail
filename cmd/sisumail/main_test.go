package main

import (
	"strings"
	"testing"
	"time"

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

