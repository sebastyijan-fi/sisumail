package knownkeys

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	Fingerprint string    `json:"fingerprint"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Store struct {
	Path string
	mu   sync.Mutex
}

func (s *Store) CheckAndUpdate(username, fingerprint string) (status string, previous string, err error) {
	username = strings.ToLower(strings.TrimSpace(username))
	fingerprint = strings.TrimSpace(fingerprint)
	if username == "" || fingerprint == "" {
		return "", "", fmt.Errorf("invalid username/fingerprint")
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0700); err != nil {
		return "", "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	m, err := s.readAllUnlocked()
	if err != nil {
		return "", "", err
	}
	old, ok := m[username]
	if !ok {
		m[username] = Entry{Fingerprint: fingerprint, UpdatedAt: time.Now().UTC()}
		if err := s.writeAllUnlocked(m); err != nil {
			return "", "", err
		}
		return "new", "", nil
	}
	if old.Fingerprint == fingerprint {
		return "unchanged", old.Fingerprint, nil
	}
	m[username] = Entry{Fingerprint: fingerprint, UpdatedAt: time.Now().UTC()}
	if err := s.writeAllUnlocked(m); err != nil {
		return "", "", err
	}
	return "changed", old.Fingerprint, nil
}

func (s *Store) readAllUnlocked() (map[string]Entry, error) {
	out := map[string]Entry{}
	b, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) writeAllUnlocked(m map[string]Entry) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}
