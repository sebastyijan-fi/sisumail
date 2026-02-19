package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"

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
	registerRemainingAPIRoutes(
		mux,
		s,
		metrics,
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

func TestAdminMessagesAndUserReadDeleteFlow(t *testing.T) {
	store, h, _ := setupAPITestServer(t, 1<<20)
	defer store.Close()
	codes, err := store.MintRootInvites(t.Context(), 1)
	if err != nil {
		t.Fatalf("mint invite: %v", err)
	}

	claimBody, _ := json.Marshal(map[string]any{
		"username":    "msguser",
		"pubkey":      "age1msg",
		"invite_code": codes[0],
	})
	claimReq := httptest.NewRequest(http.MethodPost, "/v1/claim", bytes.NewReader(claimBody))
	claimReq.RemoteAddr = "127.0.0.1:9001"
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

	adminBody := `{"username":"msguser","alias":"steam@msguser.sisumail.fi","sender":"support@example.com","ciphertext":"ciphertext:test","ttl_seconds":120}`
	adminReq := httptest.NewRequest(http.MethodPost, "/v1/admin/messages", bytes.NewBufferString(adminBody))
	adminReq.RemoteAddr = "127.0.0.1:9002"
	adminReq.Header.Set("Authorization", "Bearer admin-token")
	adminRes := httptest.NewRecorder()
	h.ServeHTTP(adminRes, adminReq)
	if adminRes.Code != http.StatusCreated {
		t.Fatalf("admin messages post expected 201 got %d body=%s", adminRes.Code, adminRes.Body.String())
	}

	meReq := httptest.NewRequest(http.MethodGet, "/v1/me/messages", nil)
	meReq.RemoteAddr = "127.0.0.1:9003"
	meReq.Header.Set("Authorization", "Bearer "+claim.APIKey)
	meRes := httptest.NewRecorder()
	h.ServeHTTP(meRes, meReq)
	if meRes.Code != http.StatusOK {
		t.Fatalf("me messages expected 200 got %d body=%s", meRes.Code, meRes.Body.String())
	}
	var meList struct {
		Items []struct {
			ID int64 `json:"id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(meRes.Body.Bytes(), &meList); err != nil {
		t.Fatalf("unmarshal me list: %v", err)
	}
	if len(meList.Items) != 1 {
		t.Fatalf("expected one message, got %d", len(meList.Items))
	}
	msgID := meList.Items[0].ID

	meDelReq := httptest.NewRequest(http.MethodDelete, "/v1/me/messages/"+strconv.FormatInt(msgID, 10), nil)
	meDelReq.RemoteAddr = "127.0.0.1:9004"
	meDelReq.Header.Set("Authorization", "Bearer "+claim.APIKey)
	meDelRes := httptest.NewRecorder()
	h.ServeHTTP(meDelRes, meDelReq)
	if meDelRes.Code != http.StatusOK {
		t.Fatalf("me delete expected 200 got %d body=%s", meDelRes.Code, meDelRes.Body.String())
	}
}

func TestAdminPurgeExpiredFlow(t *testing.T) {
	store, h, _ := setupAPITestServer(t, 1<<20)
	defer store.Close()
	codes, err := store.MintRootInvites(t.Context(), 1)
	if err != nil {
		t.Fatalf("mint invite: %v", err)
	}

	claimBody, _ := json.Marshal(map[string]any{
		"username":    "purgeuser",
		"pubkey":      "age1purge",
		"invite_code": codes[0],
	})
	claimReq := httptest.NewRequest(http.MethodPost, "/v1/claim", bytes.NewReader(claimBody))
	claimReq.RemoteAddr = "127.0.0.1:9011"
	claimRes := httptest.NewRecorder()
	h.ServeHTTP(claimRes, claimReq)
	if claimRes.Code != http.StatusCreated {
		t.Fatalf("claim expected 201 got %d", claimRes.Code)
	}

	adminBody := `{"username":"purgeuser","alias":"steam@purgeuser.sisumail.fi","sender":"support@example.com","ciphertext":"ciphertext:test","ttl_seconds":1}`
	adminReq := httptest.NewRequest(http.MethodPost, "/v1/admin/messages", bytes.NewBufferString(adminBody))
	adminReq.RemoteAddr = "127.0.0.1:9012"
	adminReq.Header.Set("Authorization", "Bearer admin-token")
	adminRes := httptest.NewRecorder()
	h.ServeHTTP(adminRes, adminReq)
	if adminRes.Code != http.StatusCreated {
		t.Fatalf("admin messages post expected 201 got %d", adminRes.Code)
	}

	time.Sleep(1200 * time.Millisecond)
	purgeReq := httptest.NewRequest(http.MethodPost, "/v1/admin/purge-expired", nil)
	purgeReq.RemoteAddr = "127.0.0.1:9013"
	purgeReq.Header.Set("Authorization", "Bearer admin-token")
	purgeRes := httptest.NewRecorder()
	h.ServeHTTP(purgeRes, purgeReq)
	if purgeRes.Code != http.StatusOK {
		t.Fatalf("purge expected 200 got %d body=%s", purgeRes.Code, purgeRes.Body.String())
	}
}

func TestInviteRequestAdminAckFlow(t *testing.T) {
	store, h, _ := setupAPITestServer(t, 1<<20)
	defer store.Close()

	reqBody := `{"email":"test@example.com","note":"hello"}`
	pubReq := httptest.NewRequest(http.MethodPost, "/v1/invite-requests", bytes.NewBufferString(reqBody))
	pubReq.RemoteAddr = "127.0.0.1:9021"
	pubRes := httptest.NewRecorder()
	h.ServeHTTP(pubRes, pubReq)
	if pubRes.Code != http.StatusCreated {
		t.Fatalf("invite request expected 201 got %d body=%s", pubRes.Code, pubRes.Body.String())
	}
	var created struct {
		RequestID int64 `json:"request_id"`
	}
	if err := json.Unmarshal(pubRes.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal created: %v", err)
	}
	if created.RequestID <= 0 {
		t.Fatalf("expected request id > 0, got %d", created.RequestID)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/v1/admin/invite-requests?status=pending", nil)
	listReq.RemoteAddr = "127.0.0.1:9022"
	listReq.Header.Set("Authorization", "Bearer admin-token")
	listRes := httptest.NewRecorder()
	h.ServeHTTP(listRes, listReq)
	if listRes.Code != http.StatusOK {
		t.Fatalf("list expected 200 got %d body=%s", listRes.Code, listRes.Body.String())
	}

	ackReq := httptest.NewRequest(http.MethodPost, "/v1/admin/invite-requests/"+strconv.FormatInt(created.RequestID, 10)+"/ack", nil)
	ackReq.RemoteAddr = "127.0.0.1:9023"
	ackReq.Header.Set("Authorization", "Bearer admin-token")
	ackRes := httptest.NewRecorder()
	h.ServeHTTP(ackRes, ackReq)
	if ackRes.Code != http.StatusOK {
		t.Fatalf("ack expected 200 got %d body=%s", ackRes.Code, ackRes.Body.String())
	}
}
