package tier2

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type SourceGuard struct {
	MaxConnsPerSource      int
	MaxMsgsPerSourcePerMin int
	nowFn                  func() time.Time

	mu             sync.Mutex
	activeBySource map[string]int
	msgWindowByIP  map[string]rateWindow
	deny           []*net.IPNet
}

type rateWindow struct {
	start time.Time
	count int
}

func NewSourceGuard(maxConnsPerSource int, maxMsgsPerSourcePerMin int, deny []*net.IPNet) *SourceGuard {
	return &SourceGuard{
		MaxConnsPerSource:      maxConnsPerSource,
		MaxMsgsPerSourcePerMin: maxMsgsPerSourcePerMin,
		nowFn:                  time.Now,
		activeBySource:         make(map[string]int),
		msgWindowByIP:          make(map[string]rateWindow),
		deny:                   deny,
	}
}

func (g *SourceGuard) IsDenied(ip net.IP) bool {
	if g == nil || ip == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, n := range g.deny {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (g *SourceGuard) TryAcquireConn(source string) bool {
	if g == nil || g.MaxConnsPerSource <= 0 {
		return true
	}
	source = strings.TrimSpace(source)
	if source == "" {
		source = "unknown"
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.activeBySource[source] >= g.MaxConnsPerSource {
		return false
	}
	g.activeBySource[source]++
	return true
}

func (g *SourceGuard) ReleaseConn(source string) {
	if g == nil || g.MaxConnsPerSource <= 0 {
		return
	}
	source = strings.TrimSpace(source)
	if source == "" {
		source = "unknown"
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	next := g.activeBySource[source] - 1
	if next <= 0 {
		delete(g.activeBySource, source)
		return
	}
	g.activeBySource[source] = next
}

func (g *SourceGuard) AllowMessage(source string) bool {
	if g == nil || g.MaxMsgsPerSourcePerMin <= 0 {
		return true
	}
	source = strings.TrimSpace(source)
	if source == "" {
		source = "unknown"
	}
	now := g.nowFn()
	g.mu.Lock()
	defer g.mu.Unlock()

	w, ok := g.msgWindowByIP[source]
	if !ok || now.Sub(w.start) >= time.Minute {
		g.msgWindowByIP[source] = rateWindow{start: now, count: 1}
		return true
	}
	if w.count >= g.MaxMsgsPerSourcePerMin {
		return false
	}
	w.count++
	g.msgWindowByIP[source] = w
	return true
}

func ParseDenylist(path string) ([]*net.IPNet, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []*net.IPNet
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Allow single IP entries by treating them as /32 or /128.
		if ip := net.ParseIP(line); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
				ip = ip.To4()
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(line)
		if err != nil {
			return nil, fmt.Errorf("denylist line %d: %w", lineNo, err)
		}
		out = append(out, n)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
