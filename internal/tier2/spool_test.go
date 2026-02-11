package tier2

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sisumail/sisumail/internal/core"
)

func TestFileSpoolPutGetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	spool := &FileSpool{Root: dir}
	testSSHPubKey, testSSHPrivKey := genTestKeyPair(t)

	// Write a message through encrypt → spool.
	plaintext := "From: sender@example.com\r\nSubject: Test\r\n\r\nHello.\r\n"

	// Use io.Pipe to simulate streaming encryption.
	pr, pw := pipeEncrypt(t, plaintext, testSSHPubKey)
	defer pr.Close()

	meta := core.SpoolMeta{
		MessageID:  "msg-001",
		Recipient:  "niklas.sisumail.fi",
		ReceivedAt: time.Now(),
		Tier:       "tier2",
	}

	if err := spool.Put("niklas", "msg-001", pr, meta); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Wait for pipe writer to finish.
	pw.Wait()

	// List should return the message.
	list, err := spool.List("niklas")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(list))
	}
	if list[0].MessageID != "msg-001" || list[0].Tier != "tier2" {
		t.Fatalf("unexpected meta: %+v", list[0])
	}
	if list[0].SizeBytes == 0 {
		t.Fatal("expected nonzero size_bytes")
	}

	// Get + decrypt should recover plaintext.
	rc, gotMeta, err := spool.Get("niklas", "msg-001")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer rc.Close()

	if gotMeta.MessageID != "msg-001" {
		t.Fatalf("meta mismatch: %+v", gotMeta)
	}

	var decrypted strings.Builder
	if err := StreamDecrypt(&decrypted, rc, testSSHPrivKey); err != nil {
		t.Fatalf("StreamDecrypt: %v", err)
	}
	if decrypted.String() != plaintext {
		t.Fatalf("plaintext mismatch:\n  got:  %q\n  want: %q", decrypted.String(), plaintext)
	}

	ctBytes, err := os.ReadFile(filepath.Join(dir, "niklas", "msg-001.age"))
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}
	if strings.Contains(string(ctBytes), plaintext) {
		t.Fatal("ciphertext file contains plaintext")
	}

	metaBytes, err := os.ReadFile(filepath.Join(dir, "niklas", "msg-001.meta"))
	if err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	if strings.Contains(string(metaBytes), "Hello.") || strings.Contains(string(metaBytes), "Subject: Test") {
		t.Fatal("metadata contains message body content")
	}
}

func TestFileSpoolAck(t *testing.T) {
	dir := t.TempDir()
	spool := &FileSpool{Root: dir}
	testSSHPubKey, _ := genTestKeyPair(t)

	pr, pw := pipeEncrypt(t, "test data", testSSHPubKey)
	defer pr.Close()

	meta := core.SpoolMeta{
		MessageID:  "msg-ack",
		Recipient:  "niklas.sisumail.fi",
		ReceivedAt: time.Now(),
		Tier:       "tier2",
	}

	_ = spool.Put("niklas", "msg-ack", pr, meta)
	pw.Wait()

	if err := spool.Ack("niklas", "msg-ack"); err != nil {
		t.Fatalf("Ack: %v", err)
	}

	list, _ := spool.List("niklas")
	if len(list) != 0 {
		t.Fatalf("expected 0 entries after ack, got %d", len(list))
	}
}

func TestFileSpoolListEmpty(t *testing.T) {
	dir := t.TempDir()
	spool := &FileSpool{Root: dir}

	list, err := spool.List("nonexistent")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(list))
	}
}

func TestFileSpoolPutRejectsPlaintextPayload(t *testing.T) {
	dir := t.TempDir()
	spool := &FileSpool{Root: dir}

	meta := core.SpoolMeta{
		MessageID:  "msg-plain",
		Recipient:  "niklas.sisumail.fi",
		ReceivedAt: time.Now(),
		Tier:       "tier2",
	}

	err := spool.Put("niklas", "msg-plain", strings.NewReader("From: sender@example.com\r\n\r\nhello\r\n"), meta)
	if err == nil {
		t.Fatal("expected rejection for non-age payload")
	}

	if _, statErr := os.Stat(filepath.Join(dir, "niklas", "msg-plain.age")); !os.IsNotExist(statErr) {
		t.Fatalf("expected no ciphertext file, got stat err=%v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "niklas", "msg-plain.meta")); !os.IsNotExist(statErr) {
		t.Fatalf("expected no metadata file, got stat err=%v", statErr)
	}
}

// --- helpers ---

type pipeWaiter struct {
	done chan struct{}
}

func (w *pipeWaiter) Wait() {
	<-w.done
}

func pipeEncrypt(t *testing.T, plaintext, pubKey string) (*os.File, *pipeWaiter) {
	t.Helper()

	// Write ciphertext to a temp file and return it as an *os.File reader.
	tmpFile, err := os.CreateTemp(t.TempDir(), "ct-*.age")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	tmpPath := tmpFile.Name()

	waiter := &pipeWaiter{done: make(chan struct{})}
	go func() {
		defer close(waiter.done)
		if err := StreamEncrypt(tmpFile, strings.NewReader(plaintext), pubKey); err != nil {
			t.Errorf("StreamEncrypt: %v", err)
		}
		tmpFile.Close()
	}()

	// Return a reader that opens the file after encryption.
	// We need to wait and then reopen.
	<-waiter.done

	f, err := os.Open(tmpPath)
	if err != nil {
		t.Fatalf("open temp: %v", err)
	}
	return f, waiter
}

func TestFileSpoolPutRejectsShortPayload(t *testing.T) {
	dir := t.TempDir()
	spool := &FileSpool{Root: dir}

	meta := core.SpoolMeta{
		MessageID:  "msg-short",
		Recipient:  "niklas.sisumail.fi",
		ReceivedAt: time.Now(),
		Tier:       "tier2",
	}

	err := spool.Put("niklas", "msg-short", io.NopCloser(strings.NewReader("abc")), meta)
	if err == nil {
		t.Fatal("expected rejection for short payload")
	}
}
