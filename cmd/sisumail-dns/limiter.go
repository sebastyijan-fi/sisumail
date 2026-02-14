package main

import (
	"net"
	"strings"
	"sync"
	"time"
)

// ipLimiter is a best-effort QPS limiter. It is not a perfect DDoS control; it
// exists to avoid accidental local overload (e.g. resolver retry storms).
type ipLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	byIP   map[string]*ipWindow
}

type ipWindow struct {
	start time.Time
	count int
}

func newIPLimiter(limit int, window time.Duration) *ipLimiter {
	if limit <= 0 || window <= 0 {
		return nil
	}
	return &ipLimiter{limit: limit, window: window, byIP: make(map[string]*ipWindow)}
}

func (l *ipLimiter) Allow(remote string) bool {
	if l == nil || l.limit <= 0 {
		return true
	}
	ip := normalizeIP(remote)
	if ip == "" {
		ip = "unknown"
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.byIP[ip]
	if w == nil || now.Sub(w.start) >= l.window {
		l.byIP[ip] = &ipWindow{start: now, count: 1}
		return true
	}
	if w.count >= l.limit {
		return false
	}
	w.count++
	return true
}

func normalizeIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	return ip.String()
}
