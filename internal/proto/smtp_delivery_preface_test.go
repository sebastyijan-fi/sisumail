package proto

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestSMTPDeliveryPrefaceRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	meta := SMTPDeliveryMeta{
		SenderIP:   net.ParseIP("203.0.113.10"),
		SenderPort: 2525,
		DestIP:     net.ParseIP("2001:db8::1"),
		ReceivedAt: time.UnixMilli(1739160000123),
	}

	if err := WriteSMTPDeliveryPreface(&buf, meta); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := ReadSMTPDeliveryPreface(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.SenderPort != meta.SenderPort {
		t.Fatalf("sender port: got %d want %d", got.SenderPort, meta.SenderPort)
	}
	if got.SenderIP.String() != meta.SenderIP.String() {
		t.Fatalf("sender ip: got %s want %s", got.SenderIP, meta.SenderIP)
	}
	if got.DestIP.String() != meta.DestIP.String() {
		t.Fatalf("dest ip: got %s want %s", got.DestIP, meta.DestIP)
	}
	if got.ReceivedAt.UnixMilli() != meta.ReceivedAt.UnixMilli() {
		t.Fatalf("received at: got %d want %d", got.ReceivedAt.UnixMilli(), meta.ReceivedAt.UnixMilli())
	}
}

