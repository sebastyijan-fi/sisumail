package chatlog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Entry struct {
	At        time.Time `json:"at"`
	Direction string    `json:"direction"` // "in" or "out"
	Peer      string    `json:"peer"`
	Message   string    `json:"message"`
}

type Store struct {
	Root string
}

func (s *Store) Init() error {
	return os.MkdirAll(s.Root, 0700)
}

func (s *Store) Append(peer, direction, message string, at time.Time) error {
	peer = sanitizePeer(peer)
	if peer == "" {
		return fmt.Errorf("empty peer")
	}
	if direction != "in" && direction != "out" {
		return fmt.Errorf("invalid direction")
	}
	if err := s.Init(); err != nil {
		return err
	}
	path := filepath.Join(s.Root, peer+".jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	e := Entry{At: at.UTC(), Direction: direction, Peer: peer, Message: message}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}

func (s *Store) List(peer string, limit int) ([]Entry, error) {
	peer = sanitizePeer(peer)
	if peer == "" {
		return nil, fmt.Errorf("empty peer")
	}
	path := filepath.Join(s.Root, peer+".jsonl")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []Entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

func sanitizePeer(peer string) string {
	peer = strings.TrimSpace(strings.ToLower(peer))
	if peer == "" {
		return ""
	}
	peer = strings.ReplaceAll(peer, "/", "_")
	peer = strings.ReplaceAll(peer, "\\", "_")
	peer = strings.ReplaceAll(peer, "..", "_")
	return peer
}
