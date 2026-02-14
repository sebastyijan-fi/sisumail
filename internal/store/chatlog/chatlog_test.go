package chatlog

import (
	"testing"
	"time"
)

func TestAppendAndList(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	now := time.Date(2026, 2, 11, 8, 0, 0, 0, time.UTC)

	if err := s.Append("bob", "out", "hello", now); err != nil {
		t.Fatalf("append out: %v", err)
	}
	if err := s.Append("bob", "in", "hi", now.Add(time.Second)); err != nil {
		t.Fatalf("append in: %v", err)
	}

	list, err := s.List("bob", 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("len: got %d", len(list))
	}
	if list[0].Direction != "out" || list[1].Direction != "in" {
		t.Fatalf("unexpected order/directions: %+v", list)
	}
}

func TestListLimit(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	base := time.Date(2026, 2, 11, 8, 0, 0, 0, time.UTC)
	_ = s.Append("alice", "in", "1", base)
	_ = s.Append("alice", "in", "2", base.Add(time.Second))
	_ = s.Append("alice", "in", "3", base.Add(2*time.Second))

	list, err := s.List("alice", 2)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 || list[0].Message != "2" || list[1].Message != "3" {
		t.Fatalf("unexpected limited list: %+v", list)
	}
}
