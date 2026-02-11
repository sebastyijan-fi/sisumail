package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sisumail/sisumail/internal/observability"
)

func TestRelayReadinessStatus(t *testing.T) {
	r := &relayReadiness{}
	ready, reason := r.status()
	if ready || reason == "" {
		t.Fatalf("expected not ready before listeners")
	}
	r.setSSHListening()
	ready, _ = r.status()
	if ready {
		t.Fatalf("expected still not ready with only ssh listener")
	}
	r.setTier1Listening()
	ready, _ = r.status()
	if !ready {
		t.Fatalf("expected ready after both listeners")
	}
}

func TestObservabilityEndpoints(t *testing.T) {
	stats := observability.NewRelayStats()
	stats.IncTier1Accepted()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = runObservabilityServer(ctx, addr, stats, func() (bool, string) { return false, "booting" }, 2*time.Second)
	}()

	base := "http://" + addr
	waitHTTP(t, base+"/-/healthz")

	resp, err := http.Get(base + "/-/healthz")
	if err != nil {
		t.Fatalf("healthz get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "ok") {
		t.Fatalf("unexpected healthz response: status=%d body=%q", resp.StatusCode, string(body))
	}

	resp, err = http.Get(base + "/-/readyz")
	if err != nil {
		t.Fatalf("readyz get: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), "booting") {
		t.Fatalf("unexpected readyz response: status=%d body=%q", resp.StatusCode, string(body))
	}

	resp, err = http.Get(base + "/metrics")
	if err != nil {
		t.Fatalf("metrics get: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected metrics status: %d", resp.StatusCode)
	}
	text := string(body)
	if !strings.Contains(text, "sisumail_tier1_connections_accepted_total 1") {
		t.Fatalf("missing expected metric in body: %q", text)
	}
}

func waitHTTP(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("http endpoint did not come up: %s", url)
}
