package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/sisumail/sisumail/internal/identity"
)

func setupAPITestServer(t *testing.T, maxJSONBytes int64) (*identity.Store, http.Handler, *appMetrics) {
	t.Helper()
	s := openHTTPTestStore(t)
	metrics := &appMetrics{}
	limits := identity.ClaimLimits{
		PerSourcePerHour: 100,
		PerSourcePerDay:  100,
		GlobalPerHour:    1000,
		GlobalPerDay:     1000,
		RetentionDays:    30,
	}
	mux := http.NewServeMux()
	registerCoreAPIRoutes(
		mux,
		s,
		metrics,
		limits,
		[]string{"admin-token"},
		[]netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		maxJSONBytes,
	)
	return s, withLogging(mux, metrics), metrics
}

func TestClaimAndMeFlow(t *testing.T) {
	store, h, _ := setupAPITestServer(t, 1<<20)
	defer store.Close()
	codes, err := store.MintRootInvites(t.Context(), 1)
	if err != nil {
		t.Fatalf("mint invite: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"username":    "alice",
		"pubkey":      "age1testpubkey",
		"invite_code": codes[0],
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/claim", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:2222"
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("claim expected 201 got %d body=%s", res.Code, res.Body.String())
	}
	var claim struct {
		Username string `json:"username"`
		APIKey   string `json:"api_key"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &claim); err != nil {
		t.Fatalf("unmarshal claim: %v", err)
	}
	if claim.Username != "alice" || claim.APIKey == "" {
		t.Fatalf("unexpected claim response: %+v", claim)
	}

	meReq := httptest.NewRequest(http.MethodGet, "/v1/me/account", nil)
	meReq.Header.Set("Authorization", "Bearer "+claim.APIKey)
	meReq.RemoteAddr = "127.0.0.1:3333"
	meRes := httptest.NewRecorder()
	h.ServeHTTP(meRes, meReq)
	if meRes.Code != http.StatusOK {
		t.Fatalf("me/account expected 200 got %d body=%s", meRes.Code, meRes.Body.String())
	}
}

func TestClaimBodyLimitReturns413(t *testing.T) {
	store, h, _ := setupAPITestServer(t, 32)
	defer store.Close()

	reqBody, _ := json.Marshal(map[string]any{
		"username":    "alice",
		"pubkey":      string(bytes.Repeat([]byte("x"), 200)),
		"invite_code": "INVITE",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/claim", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:4444"
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 got %d body=%s", res.Code, res.Body.String())
	}
}

func TestAdminMintInvitesAuthAndCIDR(t *testing.T) {
	store, h, _ := setupAPITestServer(t, 1<<20)
	defer store.Close()

	badAuthReq := httptest.NewRequest(http.MethodPost, "/v1/admin/mint-invites", bytes.NewReader([]byte(`{"n":1}`)))
	badAuthReq.RemoteAddr = "127.0.0.1:9999"
	badAuthRes := httptest.NewRecorder()
	h.ServeHTTP(badAuthRes, badAuthReq)
	if badAuthRes.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 got %d", badAuthRes.Code)
	}

	badCIDRReq := httptest.NewRequest(http.MethodPost, "/v1/admin/mint-invites", bytes.NewReader([]byte(`{"n":1}`)))
	badCIDRReq.RemoteAddr = "10.0.0.1:9999"
	badCIDRReq.Header.Set("Authorization", "Bearer admin-token")
	badCIDRRes := httptest.NewRecorder()
	h.ServeHTTP(badCIDRRes, badCIDRReq)
	if badCIDRRes.Code != http.StatusForbidden {
		t.Fatalf("expected 403 got %d", badCIDRRes.Code)
	}

	okReq := httptest.NewRequest(http.MethodPost, "/v1/admin/mint-invites", bytes.NewReader([]byte(`{"n":2}`)))
	okReq.RemoteAddr = "127.0.0.1:9999"
	okReq.Header.Set("Authorization", "Bearer admin-token")
	okRes := httptest.NewRecorder()
	h.ServeHTTP(okRes, okReq)
	if okRes.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d body=%s", okRes.Code, okRes.Body.String())
	}
}

func TestAPIKeyRotateFlow(t *testing.T) {
	store, h, _ := setupAPITestServer(t, 1<<20)
	defer store.Close()
	codes, err := store.MintRootInvites(t.Context(), 1)
	if err != nil {
		t.Fatalf("mint invite: %v", err)
	}

	claimBody, _ := json.Marshal(map[string]any{
		"username":    "rotator",
		"pubkey":      "age1rotate",
		"invite_code": codes[0],
	})
	claimReq := httptest.NewRequest(http.MethodPost, "/v1/claim", bytes.NewReader(claimBody))
	claimReq.RemoteAddr = "127.0.0.1:1212"
	claimRes := httptest.NewRecorder()
	h.ServeHTTP(claimRes, claimReq)
	if claimRes.Code != http.StatusCreated {
		t.Fatalf("claim expected 201 got %d", claimRes.Code)
	}
	var claim struct {
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal(claimRes.Body.Bytes(), &claim); err != nil {
		t.Fatalf("unmarshal claim: %v", err)
	}

	rotReq := httptest.NewRequest(http.MethodPost, "/v1/me/api-key/rotate", nil)
	rotReq.RemoteAddr = "127.0.0.1:1213"
	rotReq.Header.Set("Authorization", "Bearer "+claim.APIKey)
	rotRes := httptest.NewRecorder()
	h.ServeHTTP(rotRes, rotReq)
	if rotRes.Code != http.StatusOK {
		t.Fatalf("rotate expected 200 got %d body=%s", rotRes.Code, rotRes.Body.String())
	}
	var rot struct {
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal(rotRes.Body.Bytes(), &rot); err != nil {
		t.Fatalf("unmarshal rotate: %v", err)
	}
	if rot.APIKey == "" || rot.APIKey == claim.APIKey {
		t.Fatalf("unexpected rotated key: %q", rot.APIKey)
	}
}
