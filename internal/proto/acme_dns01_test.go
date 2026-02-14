package proto

import (
	"strings"
	"testing"
)

func TestACMEDNS01RoundTrip(t *testing.T) {
	var b strings.Builder
	req := ACMEDNS01Request{
		Op:       "present",
		Hostname: "alice.v6.sisumail.fi",
		Value:    "abc123",
	}
	if err := WriteACMEDNS01Request(&b, req); err != nil {
		t.Fatalf("WriteACMEDNS01Request: %v", err)
	}
	gotReq, err := ReadACMEDNS01Request(strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("ReadACMEDNS01Request: %v", err)
	}
	if gotReq.Op != "PRESENT" || gotReq.Hostname != req.Hostname || gotReq.Value != req.Value {
		t.Fatalf("request mismatch: got=%+v", gotReq)
	}

	b.Reset()
	if err := WriteACMEDNS01Response(&b, ACMEDNS01Response{OK: true}); err != nil {
		t.Fatalf("WriteACMEDNS01Response ok: %v", err)
	}
	resp, err := ReadACMEDNS01Response(strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("ReadACMEDNS01Response ok: %v", err)
	}
	if !resp.OK {
		t.Fatalf("expected OK response")
	}

	b.Reset()
	if err := WriteACMEDNS01Response(&b, ACMEDNS01Response{OK: false, Message: "denied"}); err != nil {
		t.Fatalf("WriteACMEDNS01Response err: %v", err)
	}
	resp, err = ReadACMEDNS01Response(strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("ReadACMEDNS01Response err: %v", err)
	}
	if resp.OK || resp.Message != "denied" {
		t.Fatalf("unexpected error response: %+v", resp)
	}
}
