package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sisumail/sisumail/internal/identity"
)

func openHTTPTestStore(t *testing.T) *identity.Store {
	t.Helper()
	db := filepath.Join(t.TempDir(), "relay-http-test.db")
	s, err := identity.Open(db, "pepper")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return s
}

func TestOperationalRoutes_HealthReadyMetrics(t *testing.T) {
	s := openHTTPTestStore(t)
	defer s.Close()
	metrics := &appMetrics{}
	metrics.claimsTotal.Add(2)
	metrics.smtpAcceptedTotal.Add(3)

	mux := http.NewServeMux()
	registerOperationalRoutes(mux, s, metrics)
	h := withLogging(mux, metrics)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("healthz expected 200 got %d", res.Code)
	}
	if res.Header().Get("X-Request-ID") == "" {
		t.Fatal("expected request id header")
	}
	if got := res.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("expected X-Frame-Options DENY, got %q", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	res = httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("readyz expected 200 got %d", res.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	res = httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("metrics expected 200 got %d", res.Code)
	}
	body := res.Body.String()
	if !strings.Contains(body, "sisumail_claims_total 2") {
		t.Fatalf("expected claims metric, got: %s", body)
	}
	if !strings.Contains(body, "sisumail_smtp_accepted_total 3") {
		t.Fatalf("expected smtp accepted metric, got: %s", body)
	}
}

func TestRequireAdmin_TokenAndCIDR(t *testing.T) {
	metrics := &appMetrics{}
	tokens := []string{"token-1"}
	cidrs, err := parseCIDRs("127.0.0.1/32")
	if err != nil {
		t.Fatalf("parseCIDRs: %v", err)
	}

	okReq := httptest.NewRequest(http.MethodGet, "/admin", nil)
	okReq.RemoteAddr = "127.0.0.1:1234"
	okReq.Header.Set("Authorization", "Bearer token-1")
	okRes := httptest.NewRecorder()
	if !requireAdmin(okRes, okReq, tokens, cidrs, metrics) {
		t.Fatal("expected admin auth success")
	}

	badTokenReq := httptest.NewRequest(http.MethodGet, "/admin", nil)
	badTokenReq.RemoteAddr = "127.0.0.1:1234"
	badTokenReq.Header.Set("Authorization", "Bearer nope")
	badTokenRes := httptest.NewRecorder()
	if requireAdmin(badTokenRes, badTokenReq, tokens, cidrs, metrics) {
		t.Fatal("expected admin auth failure for bad token")
	}
	if badTokenRes.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad token got %d", badTokenRes.Code)
	}

	badCIDRReq := httptest.NewRequest(http.MethodGet, "/admin", nil)
	badCIDRReq.RemoteAddr = "10.10.10.10:1234"
	badCIDRReq.Header.Set("Authorization", "Bearer token-1")
	badCIDRRes := httptest.NewRecorder()
	if requireAdmin(badCIDRRes, badCIDRReq, tokens, cidrs, metrics) {
		t.Fatal("expected admin auth failure for bad source")
	}
	if badCIDRRes.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for bad source got %d", badCIDRRes.Code)
	}
}

func TestReadyzFailsWhenStoreClosed(t *testing.T) {
	s := openHTTPTestStore(t)
	mux := http.NewServeMux()
	registerOperationalRoutes(mux, s, &appMetrics{})
	_ = s.Close()

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 after store close, got %d", res.Code)
	}
}
