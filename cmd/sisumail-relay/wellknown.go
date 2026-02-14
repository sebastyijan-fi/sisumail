package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func runWellKnownServer(ctx context.Context, addr, routePath, docPath string, readHeaderTimeout time.Duration) error {
	routePath = strings.TrimSpace(routePath)
	if routePath == "" {
		routePath = "/.well-known/sisu-node"
	}
	if !strings.HasPrefix(routePath, "/") {
		routePath = "/" + routePath
	}
	docPath = strings.TrimSpace(docPath)
	if docPath == "" {
		return fmt.Errorf("missing well-known document path")
	}
	if _, err := os.Stat(docPath); err != nil {
		return fmt.Errorf("well-known document unavailable: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(routePath, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
		default:
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := os.ReadFile(docPath)
		if err != nil {
			http.Error(w, "document unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(body)
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("well-known server listening on %s path=%s file=%s", addr, routePath, docPath)
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
