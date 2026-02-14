package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWellKnownServerServesDocument(t *testing.T) {
	docDir := t.TempDir()
	docPath := docDir + "/sisu-node.json"
	if err := os.WriteFile(docPath, []byte(`{"domain":"sisumail.fi","version":"sisu-v1"}`), 0600); err != nil {
		t.Fatalf("write well-known doc: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = runWellKnownServer(ctx, addr, ".well-known/sisu-node", docPath, 2*time.Second)
	}()

	base := "http://" + addr
	waitHTTP(t, base+"/.well-known/sisu-node")

	resp, err := http.Get(base + "/.well-known/sisu-node")
	if err != nil {
		t.Fatalf("get well-known: %v", err)
	}
	body, err := ioReadAllAndClose(resp)
	if err != nil {
		t.Fatalf("read well-known body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%q", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"domain":"sisumail.fi"`) {
		t.Fatalf("unexpected body: %q", body)
	}

	req, err := http.NewRequest(http.MethodPost, base+"/.well-known/sisu-node", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post request: %v", err)
	}
	_, _ = ioReadAllAndClose(resp)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for POST, got %d", resp.StatusCode)
	}

	resp, err = http.Get(base + "/missing")
	if err != nil {
		t.Fatalf("get missing: %v", err)
	}
	_, _ = ioReadAllAndClose(resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for missing path, got %d", resp.StatusCode)
	}
}

func ioReadAllAndClose(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
