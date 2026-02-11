package proto

import (
	"bytes"
	"testing"
)

func TestChatSendHeaderRoundTrip(t *testing.T) {
	var b bytes.Buffer
	if err := WriteChatSendHeader(&b, ChatSendHeader{To: "alice", SizeBytes: 42}); err != nil {
		t.Fatalf("write: %v", err)
	}
	h, _, err := ReadChatSendHeader(&b)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if h.To != "alice" || h.SizeBytes != 42 {
		t.Fatalf("unexpected header: %+v", h)
	}
}

func TestChatDeliveryHeaderRoundTrip(t *testing.T) {
	var b bytes.Buffer
	if err := WriteChatDeliveryHeader(&b, ChatDeliveryHeader{From: "bob", SizeBytes: 99}); err != nil {
		t.Fatalf("write: %v", err)
	}
	h, _, err := ReadChatDeliveryHeader(&b)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if h.From != "bob" || h.SizeBytes != 99 {
		t.Fatalf("unexpected header: %+v", h)
	}
}

func TestKeyLookupRoundTrip(t *testing.T) {
	var req bytes.Buffer
	if err := WriteKeyLookupRequest(&req, "niklas"); err != nil {
		t.Fatalf("write req: %v", err)
	}
	u, err := ReadKeyLookupRequest(&req)
	if err != nil {
		t.Fatalf("read req: %v", err)
	}
	if u != "niklas" {
		t.Fatalf("username: got %q", u)
	}

	pub := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey user@host"
	var resp bytes.Buffer
	if err := WriteKeyLookupResponse(&resp, pub); err != nil {
		t.Fatalf("write resp: %v", err)
	}
	got, err := ReadKeyLookupResponse(&resp)
	if err != nil {
		t.Fatalf("read resp: %v", err)
	}
	if got != pub {
		t.Fatalf("pubkey mismatch")
	}
}

