// Package alias implements client-side alias intelligence per §5.2.
//
// All state lives on the user's device. The relay never sees alias data.
// This module parses plus-addressed tags, tracks per-tag usage statistics,
// and runs leak-detection heuristics.
package alias

import (
	"strings"
	"sync"
	"time"

	"github.com/sisumail/sisumail/internal/core"
)

// Manager implements core.AliasTracker.
type Manager struct {
	mu   sync.RWMutex
	tags map[string]*tagState

	// LeakThreshold is the number of unique sender domains beyond the
	// expected set that triggers a leak detection. Default: 3.
	LeakThreshold int
}

type tagState struct {
	useCount      int
	firstSeen     time.Time
	lastSeen      time.Time
	senderDomains map[string]bool
}

// NewManager creates a new alias manager.
func NewManager() *Manager {
	return &Manager{
		tags:          make(map[string]*tagState),
		LeakThreshold: 3,
	}
}

// Parse extracts the local part and plus-tag from an RCPT TO address.
//
//	"mail+shopping@niklas.sisumail.fi" → ("mail", "shopping")
//	"mail@niklas.sisumail.fi"          → ("mail", "")
func (m *Manager) Parse(rcptTo string) (localPart, tag string) {
	// Strip domain.
	addr := rcptTo
	if idx := strings.LastIndex(addr, "@"); idx >= 0 {
		addr = addr[:idx]
	}

	// Split on "+".
	if idx := strings.Index(addr, "+"); idx >= 0 {
		return addr[:idx], addr[idx+1:]
	}
	return addr, ""
}

// RecordUse tracks a usage event for a tag.
func (m *Manager) RecordUse(tag, senderDomain string, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ts, ok := m.tags[tag]
	if !ok {
		ts = &tagState{
			firstSeen:     at,
			senderDomains: make(map[string]bool),
		}
		m.tags[tag] = ts
	}

	ts.useCount++
	if at.After(ts.lastSeen) {
		ts.lastSeen = at
	}
	if at.Before(ts.firstSeen) {
		ts.firstSeen = at
	}
	ts.senderDomains[strings.ToLower(senderDomain)] = true
}

// Stats returns usage statistics for a tag.
func (m *Manager) Stats(tag string) (core.AliasStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ts, ok := m.tags[tag]
	if !ok {
		return core.AliasStats{Tag: tag}, nil
	}

	domains := make([]string, 0, len(ts.senderDomains))
	for d := range ts.senderDomains {
		domains = append(domains, d)
	}

	return core.AliasStats{
		Tag:           tag,
		UseCount:      ts.useCount,
		FirstSeen:     ts.firstSeen,
		LastSeen:      ts.lastSeen,
		UniqueSenders: len(ts.senderDomains),
		SenderDomains: domains,
		ProbableLeak:  m.isLeaked(ts),
	}, nil
}

// DetectLeak returns true if the tag shows signs of being leaked.
//
// Heuristic: a tag is "probably leaked" if the number of unique sender
// domains exceeds the LeakThreshold. The rationale is that a tag given
// to a single service should only receive mail from a small set of
// domains. If many unrelated domains start using it, the tag was likely
// shared or sold.
func (m *Manager) DetectLeak(tag string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ts, ok := m.tags[tag]
	if !ok {
		return false
	}
	return m.isLeaked(ts)
}

// ListTags returns all known tags.
func (m *Manager) ListTags() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tags := make([]string, 0, len(m.tags))
	for t := range m.tags {
		tags = append(tags, t)
	}
	return tags, nil
}

func (m *Manager) isLeaked(ts *tagState) bool {
	threshold := m.LeakThreshold
	if threshold <= 0 {
		threshold = 3
	}
	return len(ts.senderDomains) >= threshold
}
