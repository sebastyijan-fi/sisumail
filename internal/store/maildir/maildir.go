// Package maildir implements standard Maildir message storage for the
// Sisumail client (§5.2 — edge storage, client-side only).
//
// Layout follows the Maildir specification:
//
//	<root>/new/   — newly delivered, unread messages
//	<root>/cur/   — messages that have been seen
//	<root>/tmp/   — atomicity staging area
//
// Filenames follow the standard Maildir naming convention:
//
//	<unix_ns>.<unique>.<hostname>:2,<flags>
package maildir

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sisumail/sisumail/internal/core"
)

// Store implements core.MaildirStore.
type Store struct {
	Root string // maildir root directory
}

// Init ensures the Maildir directory structure exists.
func (s *Store) Init() error {
	for _, sub := range []string{"new", "cur", "tmp"} {
		if err := os.MkdirAll(filepath.Join(s.Root, sub), 0700); err != nil {
			return fmt.Errorf("maildir init %s: %w", sub, err)
		}
	}
	return nil
}

// Deliver writes a message to the Maildir atomically.
// Returns a unique message ID.
func (s *Store) Deliver(msg io.Reader, tier string) (string, error) {
	if err := s.Init(); err != nil {
		return "", err
	}

	now := time.Now()
	host, _ := os.Hostname()
	if host == "" {
		host = "localhost"
	}
	// Unique ID: timestamp_ns.pid.hostname
	id := fmt.Sprintf("%d.%d.%s", now.UnixNano(), os.Getpid(), host)

	// Standard Maildir flags: we add a custom T<tier> info suffix.
	filename := fmt.Sprintf("%s:2,T%s", id, tier)

	// Write to tmp/ first.
	tmpPath := filepath.Join(s.Root, "tmp", filename)
	f, err := os.Create(tmpPath)
	if err != nil {
		return "", fmt.Errorf("maildir create tmp: %w", err)
	}
	if _, err := io.Copy(f, msg); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("maildir write: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("maildir close: %w", err)
	}

	// Rename to new/.
	newPath := filepath.Join(s.Root, "new", filename)
	if err := os.Rename(tmpPath, newPath); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("maildir rename: %w", err)
	}

	return id, nil
}

// List returns all messages in new/ and cur/.
func (s *Store) List() ([]core.MaildirEntry, error) {
	var entries []core.MaildirEntry

	for _, sub := range []string{"new", "cur"} {
		dir := filepath.Join(s.Root, sub)
		files, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("maildir list %s: %w", sub, err)
		}
		for _, f := range files {
			if f.IsDir() || strings.HasPrefix(f.Name(), ".") {
				continue
			}
			entry, err := parseFilename(f.Name())
			if err != nil {
				continue // skip malformed files
			}
			info, _ := f.Info()
			if info != nil {
				entry.Size = info.Size()
			}
			entries = append(entries, entry)
		}
	}

	// Sort newest first.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})

	return entries, nil
}

// Read opens a message file for reading.
func (s *Store) Read(id string) (io.ReadCloser, error) {
	// Search new/ and cur/ for a file matching this ID.
	for _, sub := range []string{"new", "cur"} {
		dir := filepath.Join(s.Root, sub)
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if strings.HasPrefix(f.Name(), id) {
				return os.Open(filepath.Join(dir, f.Name()))
			}
		}
	}
	return nil, fmt.Errorf("message %s not found", id)
}

// parseFilename extracts metadata from a Maildir filename.
// Format: <unix_ns>.<pid>.<hostname>:2,T<tier>
func parseFilename(name string) (core.MaildirEntry, error) {
	entry := core.MaildirEntry{Filename: name}

	// Split on ":"
	parts := strings.SplitN(name, ":", 2)
	if len(parts) != 2 {
		return entry, fmt.Errorf("no info separator")
	}

	// Parse ID: <unix_ns>.<pid>.<hostname>
	entry.ID = parts[0]
	idParts := strings.SplitN(parts[0], ".", 3)
	if len(idParts) >= 1 {
		ns, err := strconv.ParseInt(idParts[0], 10, 64)
		if err == nil {
			entry.Timestamp = time.Unix(0, ns)
		}
	}

	// Parse flags after "2,"
	flags := strings.TrimPrefix(parts[1], "2,")
	if strings.HasPrefix(flags, "T") {
		entry.Tier = flags[1:]
	}

	return entry, nil
}
