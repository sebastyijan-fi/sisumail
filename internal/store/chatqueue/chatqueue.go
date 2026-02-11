package chatqueue

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Meta struct {
	ID         string    `json:"id"`
	From       string    `json:"from"`
	To         string    `json:"to"`
	SizeBytes  int64     `json:"size_bytes"`
	ReceivedAt time.Time `json:"received_at"`
}

type Store struct {
	Root string
}

func (s *Store) Put(to, id string, ciphertext io.Reader, meta Meta) error {
	dir := filepath.Join(s.Root, to)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("chatqueue mkdir: %w", err)
	}

	ctPath := filepath.Join(dir, id+".chat")
	ctTmp := ctPath + ".tmp"
	f, err := os.Create(ctTmp)
	if err != nil {
		return fmt.Errorf("chatqueue create tmp: %w", err)
	}
	n, err := io.Copy(f, ciphertext)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(ctTmp)
		return fmt.Errorf("chatqueue write: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(ctTmp)
		return fmt.Errorf("chatqueue close: %w", err)
	}

	meta.SizeBytes = n
	metaPath := filepath.Join(dir, id+".meta")
	metaTmp := metaPath + ".tmp"
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		_ = os.Remove(ctTmp)
		return err
	}
	if err := os.WriteFile(metaTmp, b, 0600); err != nil {
		_ = os.Remove(ctTmp)
		return err
	}
	if err := os.Rename(metaTmp, metaPath); err != nil {
		_ = os.Remove(ctTmp)
		_ = os.Remove(metaTmp)
		return err
	}
	if err := os.Rename(ctTmp, ctPath); err != nil {
		_ = os.Remove(ctTmp)
		return err
	}
	return nil
}

func (s *Store) List(to string) ([]Meta, error) {
	dir := filepath.Join(s.Root, to)
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]Meta, 0, len(ents))
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".meta") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var m Meta
		if err := json.Unmarshal(b, &m); err != nil {
			continue
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ReceivedAt.Before(out[j].ReceivedAt)
	})
	return out, nil
}

func (s *Store) Get(to, id string) (io.ReadCloser, Meta, error) {
	dir := filepath.Join(s.Root, to)
	metaPath := filepath.Join(dir, id+".meta")
	ctPath := filepath.Join(dir, id+".chat")
	var m Meta
	b, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, m, err
	}
	f, err := os.Open(ctPath)
	if err != nil {
		return nil, m, err
	}
	return f, m, nil
}

func (s *Store) Ack(to, id string) error {
	dir := filepath.Join(s.Root, to)
	var errs []string
	if err := os.Remove(filepath.Join(dir, id+".chat")); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err.Error())
	}
	if err := os.Remove(filepath.Join(dir, id+".meta")); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("chatqueue ack: %s", strings.Join(errs, "; "))
	}
	return nil
}
