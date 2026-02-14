package chatqueue

import (
	"io"
	"strings"
	"testing"
	"time"
)

func TestPutListGetAck(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	meta := Meta{
		ID:         "m1",
		From:       "alice",
		To:         "bob",
		ReceivedAt: time.Now(),
	}
	payload := "age-encryption.org/v1\n-> stub\nciphertext\n"

	if err := s.Put("bob", "m1", strings.NewReader(payload), meta); err != nil {
		t.Fatalf("Put: %v", err)
	}
	list, err := s.List("bob")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].From != "alice" || list[0].To != "bob" {
		t.Fatalf("unexpected list: %+v", list)
	}

	rc, got, err := s.Get("bob", "m1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer rc.Close()
	b, _ := io.ReadAll(rc)
	if string(b) != payload {
		t.Fatalf("payload mismatch")
	}
	if got.SizeBytes != int64(len(payload)) {
		t.Fatalf("size mismatch: got %d", got.SizeBytes)
	}

	if err := s.Ack("bob", "m1"); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	list, err = s.List("bob")
	if err != nil {
		t.Fatalf("List after ack: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty queue after ack")
	}
}
