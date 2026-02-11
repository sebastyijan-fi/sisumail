package tier2

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sisumail/sisumail/internal/core"
)

// FileSpool implements core.SpoolStore using the filesystem.
//
// Layout:
//
//	<root>/<user>/<msgID>.age   — ciphertext
//	<root>/<user>/<msgID>.meta  — JSON metadata
//
// Writes are atomic: data goes to .tmp first, then renamed.
type FileSpool struct {
	Root string // spool root directory
}

const ageCiphertextHeader = "age-encryption.org/v1\n"

// Put writes ciphertext and metadata atomically.
func (s *FileSpool) Put(user, msgID string, ciphertext io.Reader, meta core.SpoolMeta) error {
	// Enforce ciphertext-only storage: Tier 2 spool files must contain age payloads.
	br := bufio.NewReader(ciphertext)
	head, err := br.Peek(len(ageCiphertextHeader))
	if err != nil {
		return fmt.Errorf("spool validate ciphertext header: %w", err)
	}
	if string(head) != ageCiphertextHeader {
		return fmt.Errorf("spool reject non-age payload")
	}

	dir := filepath.Join(s.Root, user)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("spool mkdir: %w", err)
	}

	// Write ciphertext to tmp, then rename.
	ctPath := filepath.Join(dir, msgID+".age")
	ctTmp := ctPath + ".tmp"
	f, err := os.Create(ctTmp)
	if err != nil {
		return fmt.Errorf("spool create tmp: %w", err)
	}

	n, err := io.Copy(f, br)
	if err != nil {
		f.Close()
		os.Remove(ctTmp)
		return fmt.Errorf("spool write ciphertext: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(ctTmp)
		return fmt.Errorf("spool close: %w", err)
	}

	meta.SizeBytes = n

	// Write metadata.
	metaPath := filepath.Join(dir, msgID+".meta")
	metaTmp := metaPath + ".tmp"
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		os.Remove(ctTmp)
		return fmt.Errorf("spool marshal meta: %w", err)
	}
	if err := os.WriteFile(metaTmp, metaBytes, 0600); err != nil {
		os.Remove(ctTmp)
		return fmt.Errorf("spool write meta: %w", err)
	}

	// Atomic rename: meta first so we never have ciphertext without metadata.
	if err := os.Rename(metaTmp, metaPath); err != nil {
		os.Remove(ctTmp)
		os.Remove(metaTmp)
		return err
	}
	if err := os.Rename(ctTmp, ctPath); err != nil {
		os.Remove(ctTmp)
		return err
	}

	return nil
}

// Get returns the ciphertext reader and metadata for a spooled message.
func (s *FileSpool) Get(user, msgID string) (io.ReadCloser, core.SpoolMeta, error) {
	dir := filepath.Join(s.Root, user)

	// Read metadata.
	metaPath := filepath.Join(dir, msgID+".meta")
	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, core.SpoolMeta{}, fmt.Errorf("spool read meta: %w", err)
	}
	var meta core.SpoolMeta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, core.SpoolMeta{}, fmt.Errorf("spool parse meta: %w", err)
	}

	// Open ciphertext.
	ctPath := filepath.Join(dir, msgID+".age")
	f, err := os.Open(ctPath)
	if err != nil {
		return nil, core.SpoolMeta{}, fmt.Errorf("spool open ciphertext: %w", err)
	}

	return f, meta, nil
}

// Ack marks a message as delivered by deleting it from the spool.
func (s *FileSpool) Ack(user, msgID string) error {
	dir := filepath.Join(s.Root, user)
	ctPath := filepath.Join(dir, msgID+".age")
	metaPath := filepath.Join(dir, msgID+".meta")

	// Remove both; ignore "not found" errors.
	var errs []string
	if err := os.Remove(ctPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err.Error())
	}
	if err := os.Remove(metaPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("spool ack: %s", strings.Join(errs, "; "))
	}
	return nil
}

// List returns metadata for all spooled messages for a user.
func (s *FileSpool) List(user string) ([]core.SpoolMeta, error) {
	dir := filepath.Join(s.Root, user)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("spool list: %w", err)
	}

	var out []core.SpoolMeta
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".meta") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var meta core.SpoolMeta
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}
		out = append(out, meta)
	}
	return out, nil
}
