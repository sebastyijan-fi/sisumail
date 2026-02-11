package maildir

import (
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestDeliverAndList(t *testing.T) {
	dir := t.TempDir()
	store := &Store{Root: dir}

	msg := "From: sender@example.com\r\nSubject: Test\r\n\r\nBody.\r\n"
	id, err := store.Deliver(strings.NewReader(msg), "tier1")
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if id == "" {
		t.Fatal("empty ID")
	}

	entries, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Tier != "tier1" {
		t.Fatalf("tier: got %q, want tier1", entries[0].Tier)
	}
	if entries[0].Size == 0 {
		t.Fatal("expected nonzero size")
	}
}

func TestDeliverAndRead(t *testing.T) {
	dir := t.TempDir()
	store := &Store{Root: dir}

	msg := "From: test@example.com\r\nSubject: Hello\r\n\r\nWorld.\r\n"
	id, err := store.Deliver(strings.NewReader(msg), "tier2")
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	rc, err := store.Read(id)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(data) != msg {
		t.Fatalf("content mismatch:\n  got:  %q\n  want: %q", string(data), msg)
	}
}

func TestReadNotFound(t *testing.T) {
	dir := t.TempDir()
	store := &Store{Root: dir}
	_ = store.Init()

	_, err := store.Read("nonexistent-id")
	if err == nil {
		t.Fatal("expected error for nonexistent message")
	}
}

func TestConcurrentDelivery(t *testing.T) {
	dir := t.TempDir()
	store := &Store{Root: dir}

	var wg sync.WaitGroup
	errs := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			msg := strings.NewReader("message content")
			if _, err := store.Deliver(msg, "tier1"); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent deliver: %v", err)
	}

	entries, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 20 {
		t.Fatalf("expected 20 entries, got %d", len(entries))
	}
}

func TestTierLabel(t *testing.T) {
	dir := t.TempDir()
	store := &Store{Root: dir}

	store.Deliver(strings.NewReader("msg1"), "tier1")
	store.Deliver(strings.NewReader("msg2"), "tier2")

	entries, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	tiers := map[string]bool{}
	for _, e := range entries {
		tiers[e.Tier] = true
	}
	if !tiers["tier1"] || !tiers["tier2"] {
		t.Fatalf("missing tier labels: %v", tiers)
	}
}

func TestListEmptyMaildir(t *testing.T) {
	dir := t.TempDir()
	store := &Store{Root: dir}
	_ = store.Init()

	entries, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestMaildirDirStructure(t *testing.T) {
	dir := t.TempDir()
	store := &Store{Root: dir}

	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	for _, sub := range []string{"new", "cur", "tmp"} {
		path := dir + "/" + sub
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("missing %s: %v", sub, err)
		}
		if !info.IsDir() {
			t.Fatalf("%s is not a directory", sub)
		}
	}
}

func TestMarkReadMovesFromNewToCur(t *testing.T) {
	dir := t.TempDir()
	store := &Store{Root: dir}

	id, err := store.Deliver(strings.NewReader("From: a@b\r\n\r\nx\r\n"), "tier1")
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	entries, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].Seen {
		t.Fatalf("expected unread entry, got %+v", entries)
	}

	if err := store.MarkRead(id); err != nil {
		t.Fatalf("MarkRead: %v", err)
	}

	entries, err = store.List()
	if err != nil {
		t.Fatalf("List after mark read: %v", err)
	}
	if len(entries) != 1 || !entries[0].Seen {
		t.Fatalf("expected seen entry, got %+v", entries)
	}
}
