package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sisumail/sisumail/internal/observability"
)

type relayReadiness struct {
	sshListening   atomic.Bool
	tier1Listening atomic.Bool
}

func (r *relayReadiness) setSSHListening()   { r.sshListening.Store(true) }
func (r *relayReadiness) setTier1Listening() { r.tier1Listening.Store(true) }

func (r *relayReadiness) status() (bool, string) {
	if !r.sshListening.Load() {
		return false, "ssh listener not ready"
	}
	if !r.tier1Listening.Load() {
		return false, "tier1 listener not ready"
	}
	return true, "ready"
}

type tier1MetricsObserver struct {
	stats *observability.RelayStats
	ready *relayReadiness
}

func (o *tier1MetricsObserver) OnListening(addr string) { o.ready.setTier1Listening() }
func (o *tier1MetricsObserver) OnAccepted()             { o.stats.IncTier1Accepted() }
func (o *tier1MetricsObserver) OnClosed()               { o.stats.IncTier1Closed() }
func (o *tier1MetricsObserver) OnChannelOpenTimeout()   { o.stats.IncTier1OpenTimeout() }
func (o *tier1MetricsObserver) OnChannelOpenError()     { o.stats.IncTier1ChannelOpenError() }
func (o *tier1MetricsObserver) OnPrefaceError()         { o.stats.IncTier1PrefaceError() }
func (o *tier1MetricsObserver) OnRejected(reason string) {
	switch strings.TrimSpace(reason) {
	case "no_session":
		o.stats.IncTier1RejectNoSession()
	case "user_cap":
		o.stats.IncTier1RejectUserCap()
	case "source_cap":
		o.stats.IncTier1RejectSourceCap()
	case "unknown_dest":
		o.stats.IncTier1RejectUnknownIP()
	case "open_failed":
		o.stats.IncTier1RejectOpenFailed()
	}
}

func runObservabilityServer(ctx context.Context, addr string, stats *observability.RelayStats, readyFn func() (bool, string), readHeaderTimeout time.Duration) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/-/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/-/readyz", func(w http.ResponseWriter, r *http.Request) {
		ready, reason := readyFn()
		if !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(fmt.Sprintf("not ready: %s\n", reason)))
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(stats.Prometheus()))
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("observability listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		return err
	}
}
