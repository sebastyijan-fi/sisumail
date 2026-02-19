package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sisumail/sisumail/internal/identity"
)

type appMetrics struct {
	httpRequestsTotal      atomic.Int64
	httpErrorsTotal        atomic.Int64
	httpAuthFailuresTotal  atomic.Int64
	claimsTotal            atomic.Int64
	claimFailuresTotal     atomic.Int64
	smtpAcceptedTotal      atomic.Int64
	smtpRejectedTotal      atomic.Int64
	smtpConnectionsCurrent atomic.Int64
	smtpConnectionsTotal   atomic.Int64
	purgeRemovedTotal      atomic.Int64
}

type appConfig struct {
	metricsToken string
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func main() {
	var (
		listen                = flag.String("listen", ":8080", "API listen address")
		smtpListen            = flag.String("smtp-listen", ":2525", "SMTP ingress listen address (empty disables)")
		smtpZone              = flag.String("smtp-zone", "sisumail.fi", "SMTP recipient base zone")
		spoolTTL              = flag.Duration("spool-ttl", 15*time.Minute, "ciphertext spool TTL")
		dbPath                = flag.String("db", "./sisumail-relay.db", "sqlite db path")
		pepper                = flag.String("invite-pepper", "", "invite hash pepper")
		adminToken            = flag.String("admin-token", "", "admin bearer token(s), comma-separated")
		adminAllowCIDRs       = flag.String("admin-allow-cidrs", "", "optional comma-separated CIDRs allowed for admin API access")
		metricsToken          = flag.String("metrics-token", "", "optional bearer token required for /metrics")
		purgeInterval         = flag.Duration("purge-interval", 30*time.Second, "expired spool purge interval (0 disables)")
		siteDir               = flag.String("site-dir", "./web", "landing page directory")
		maxJSONBytes          = flag.Int64("max-json-bytes", 1<<20, "maximum bytes accepted for JSON API bodies")
		maxHeaderBytes        = flag.Int("max-header-bytes", 1<<20, "maximum HTTP header bytes")
		maxCiphertextBytes    = flag.Int("max-ciphertext-bytes", 256*1024, "maximum ciphertext payload size in bytes")
		apiKeyRetention       = flag.Duration("api-key-retention", 30*24*time.Hour, "retention window for revoked API key metadata")
		httpReadTimeout       = flag.Duration("http-read-timeout", 10*time.Second, "HTTP server read timeout")
		httpWriteTimeout      = flag.Duration("http-write-timeout", 15*time.Second, "HTTP server write timeout")
		httpIdleTimeout       = flag.Duration("http-idle-timeout", 60*time.Second, "HTTP server idle timeout")
		smtpMaxConn           = flag.Int("smtp-max-connections", 200, "maximum concurrent SMTP sessions")
		smtpPerIPPerMinute    = flag.Int("smtp-per-ip-per-minute", 120, "maximum accepted SMTP commands per IP per minute")
		smtpMaxDataBytes      = flag.Int("smtp-max-data-bytes", 256*1024, "maximum SMTP DATA size in bytes")
		smtpMaxRcptPerSession = flag.Int("smtp-max-rcpt-per-session", 10, "maximum RCPT commands per SMTP session")
	)
	flag.Parse()
	if strings.TrimSpace(*pepper) == "" {
		*pepper = strings.TrimSpace(os.Getenv("SISUMAIL_INVITE_PEPPER"))
	}
	if strings.TrimSpace(*adminToken) == "" {
		*adminToken = strings.TrimSpace(os.Getenv("SISUMAIL_ADMIN_TOKEN"))
	}
	if strings.TrimSpace(*adminAllowCIDRs) == "" {
		*adminAllowCIDRs = strings.TrimSpace(os.Getenv("SISUMAIL_ADMIN_ALLOW_CIDRS"))
	}
	if strings.TrimSpace(*metricsToken) == "" {
		*metricsToken = strings.TrimSpace(os.Getenv("SISUMAIL_METRICS_TOKEN"))
	}
	if strings.TrimSpace(*pepper) == "" {
		log.Printf("WARNING: invite pepper is empty; invite/api key hashing is weakened")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	store, err := identity.Open(*dbPath, *pepper)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	limits := identity.ClaimLimits{
		PerSourcePerHour: 3,
		PerSourcePerDay:  12,
		GlobalPerHour:    200,
		GlobalPerDay:     1000,
		RetentionDays:    30,
	}
	metrics := &appMetrics{}
	cfg := &appConfig{
		metricsToken: strings.TrimSpace(*metricsToken),
	}
	adminTokens := parseAdminTokens(*adminToken)
	adminCIDRs, err := parseCIDRs(*adminAllowCIDRs)
	if err != nil {
		log.Fatalf("invalid admin allow cidrs: %v", err)
	}
	store.SetMaxCiphertextBytes(*maxCiphertextBytes)
	store.SetAPIKeyRetention(*apiKeyRetention)

	mux := http.NewServeMux()
	if dirExists(*siteDir) {
		serveStaticSite(mux, *siteDir)
	} else {
		log.Printf("site dir %q not found; landing routes disabled", *siteDir)
	}
	registerOperationalRoutes(mux, store, metrics, cfg)
	registerCoreAPIRoutes(mux, store, metrics, limits, adminTokens, adminCIDRs, *maxJSONBytes)
	registerRemainingAPIRoutes(mux, store, metrics, adminTokens, adminCIDRs, *maxJSONBytes)

	h := withRecover(withLogging(mux, metrics))
	log.Printf("relay api listening on %s", *listen)
	s := &http.Server{
		Addr:              *listen,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       *httpReadTimeout,
		WriteTimeout:      *httpWriteTimeout,
		IdleTimeout:       *httpIdleTimeout,
		MaxHeaderBytes:    *maxHeaderBytes,
	}
	smtp := &smtpIngress{
		listenAddr:        strings.TrimSpace(*smtpListen),
		zone:              strings.TrimSpace(*smtpZone),
		store:             store,
		ttl:               *spoolTTL,
		maxConcurrent:     *smtpMaxConn,
		perIPPerMinute:    *smtpPerIPPerMinute,
		maxDataBytes:      *smtpMaxDataBytes,
		maxRcptPerSession: *smtpMaxRcptPerSession,
		metrics:           metrics,
	}
	if *purgeInterval > 0 {
		go runPurgeWorker(ctx, store, *purgeInterval, metrics)
	}
	go func() {
		if err := smtp.run(ctx); err != nil {
			log.Printf("smtp ingress stopped: %v", err)
			cancel()
		}
	}()
	go func() {
		<-ctx.Done()
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(shCtx)
	}()
	if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic recovered path=%q remote=%q panic=%v", r.URL.Path, r.RemoteAddr, rec)
				writeErr(w, http.StatusInternalServerError, "internal_error", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func withLogging(next http.Handler, metrics *appMetrics) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rid := requestID()
		sw := &statusWriter{ResponseWriter: w}
		applySecurityHeaders(sw.Header())
		sw.Header().Set("X-Request-ID", rid)
		metrics.httpRequestsTotal.Add(1)
		next.ServeHTTP(sw, r)
		if sw.status >= 400 {
			metrics.httpErrorsTotal.Add(1)
		}
		log.Printf("request_id=%s method=%s path=%s status=%d bytes=%d remote=%q dur_ms=%d",
			rid, r.Method, r.URL.Path, sw.status, sw.bytes, r.RemoteAddr, time.Since(start).Milliseconds())
	})
}

func requireMetricsAuth(w http.ResponseWriter, r *http.Request, cfg *appConfig) bool {
	if cfg == nil || strings.TrimSpace(cfg.metricsToken) == "" {
		return true
	}
	presented, ok := bearerToken(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "metrics token required")
		return false
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(presented)), []byte(strings.TrimSpace(cfg.metricsToken))) != 1 {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "metrics token required")
		return false
	}
	return true
}

func sourceBucket(remote string) string {
	h, _, err := net.SplitHostPort(strings.TrimSpace(remote))
	if err != nil {
		return "unknown"
	}
	return h
}

func requireAdmin(w http.ResponseWriter, r *http.Request, tokens []string, cidrs []netip.Prefix, metrics *appMetrics) bool {
	if !isRemoteAllowed(r.RemoteAddr, cidrs) {
		metrics.httpAuthFailuresTotal.Add(1)
		writeErr(w, http.StatusForbidden, "forbidden", "admin source not allowed")
		return false
	}
	presented, ok := bearerToken(r)
	if !ok || !isValidAdminToken(presented, tokens) {
		metrics.httpAuthFailuresTotal.Add(1)
		writeErr(w, http.StatusUnauthorized, "unauthorized", "admin token required")
		return false
	}
	return true
}

func applySecurityHeaders(h http.Header) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
}

func bearerToken(r *http.Request) (string, bool) {
	a := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(a, "Bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(strings.TrimPrefix(a, "Bearer "))
	if tok == "" {
		return "", false
	}
	return tok, true
}

func userFromAPIKey(w http.ResponseWriter, r *http.Request, store *identity.Store) (string, bool) {
	presented, ok := bearerToken(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "api key required")
		return "", false
	}
	username, err := store.AuthenticateAPIKey(r.Context(), presented)
	if err != nil {
		mapIdentityErr(w, err)
		return "", false
	}
	return username, true
}

func mapIdentityErr(w http.ResponseWriter, err error) {
	switch err {
	case identity.ErrNotFound:
		writeErr(w, http.StatusNotFound, "not_found", "not found")
	case identity.ErrUnauthorized:
		writeErr(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
	default:
		msg := strings.ToLower(strings.TrimSpace(err.Error()))
		if strings.Contains(msg, "invalid") || strings.Contains(msg, "missing") {
			writeErr(w, http.StatusBadRequest, "request_failed", err.Error())
			return
		}
		log.Printf("internal request failure err=%v", err)
		writeErr(w, http.StatusInternalServerError, "internal_error", "internal error")
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, out any, limit int64) error {
	if limit <= 0 {
		limit = 1 << 20
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("invalid trailing json")
		}
		return err
	}
	return nil
}

func handleDecodeErr(w http.ResponseWriter, err error) {
	var mbErr *http.MaxBytesError
	if errors.As(err, &mbErr) {
		writeErr(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body too large")
		return
	}
	writeErr(w, http.StatusBadRequest, "invalid_request", "bad json")
}

func parseAdminTokens(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

func parseCIDRs(raw string) ([]netip.Prefix, error) {
	parts := strings.Split(raw, ",")
	out := make([]netip.Prefix, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t == "" {
			continue
		}
		pr, err := netip.ParsePrefix(t)
		if err != nil {
			return nil, err
		}
		out = append(out, pr)
	}
	return out, nil
}

func isRemoteAllowed(remote string, cidrs []netip.Prefix) bool {
	if len(cidrs) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(remote))
	if err != nil {
		host = strings.TrimSpace(remote)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, pr := range cidrs {
		if pr.Contains(addr) {
			return true
		}
	}
	return false
}

func isValidAdminToken(presented string, tokens []string) bool {
	p := strings.TrimSpace(presented)
	if p == "" || len(tokens) == 0 {
		return false
	}
	for _, candidate := range tokens {
		if subtle.ConstantTimeCompare([]byte(p), []byte(candidate)) == 1 {
			return true
		}
	}
	return false
}

func requestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("req_%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("req_%x", b[:])
}

func auditLog(r *http.Request, action, target, outcome string) {
	log.Printf("audit action=%q target=%q outcome=%q remote=%q path=%q", action, target, outcome, r.RemoteAddr, r.URL.Path)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": message}})
}

func parseInt64(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	var out int64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("non-digit")
		}
		out = out*10 + int64(r-'0')
	}
	return out, nil
}

func registerOperationalRoutes(mux *http.ServeMux, store *identity.Store, metrics *appMetrics, cfg *appConfig) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := store.Ping(r.Context()); err != nil {
			writeErr(w, http.StatusServiceUnavailable, "not_ready", "database unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if !requireMetricsAuth(w, r, cfg) {
			return
		}
		writeMetrics(w, metrics)
	})
}

func registerCoreAPIRoutes(
	mux *http.ServeMux,
	store *identity.Store,
	metrics *appMetrics,
	limits identity.ClaimLimits,
	adminTokens []string,
	adminCIDRs []netip.Prefix,
	maxJSONBytes int64,
) {
	mux.HandleFunc("/v1/claim", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
			return
		}
		var req struct {
			Username   string `json:"username"`
			PubKey     string `json:"pubkey"`
			InviteCode string `json:"invite_code"`
		}
		if err := decodeJSON(w, r, &req, maxJSONBytes); err != nil {
			handleDecodeErr(w, err)
			return
		}
		src := sourceBucket(r.RemoteAddr)
		acc, children, err := store.ClaimWithInvite(r.Context(), req.Username, req.PubKey, req.InviteCode, src, limits)
		if err != nil {
			metrics.claimFailuresTotal.Add(1)
			switch err {
			case identity.ErrInviteInvalid:
				writeErr(w, http.StatusBadRequest, "invite_invalid", err.Error())
			case identity.ErrInviteRedeemed:
				writeErr(w, http.StatusConflict, "invite_redeemed", err.Error())
			case identity.ErrClaimRateLimited:
				writeErr(w, http.StatusTooManyRequests, "rate_limited", err.Error())
			case identity.ErrUsernameTaken:
				writeErr(w, http.StatusConflict, "username_taken", err.Error())
			default:
				log.Printf("claim failed remote=%q err=%v", r.RemoteAddr, err)
				writeErr(w, http.StatusBadRequest, "claim_failed", "claim failed")
			}
			return
		}
		apiKey, err := store.IssueAPIKey(r.Context(), acc.Username)
		if err != nil {
			metrics.claimFailuresTotal.Add(1)
			log.Printf("issue api key failed user=%q err=%v", acc.Username, err)
			writeErr(w, http.StatusInternalServerError, "api_key_issue_failed", "internal error")
			return
		}
		metrics.claimsTotal.Add(1)
		writeJSON(w, http.StatusCreated, map[string]any{
			"username":      acc.Username,
			"status":        acc.Status,
			"child_invites": children,
			"api_key":       apiKey,
		})
	})

	mux.HandleFunc("/v1/admin/mint-invites", func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r, adminTokens, adminCIDRs, metrics) {
			return
		}
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
			return
		}
		var req struct {
			N int `json:"n"`
		}
		if err := decodeJSON(w, r, &req, maxJSONBytes); err != nil && !errors.Is(err, io.EOF) {
			handleDecodeErr(w, err)
			return
		}
		if req.N <= 0 {
			req.N = 1
		}
		codes, err := store.MintRootInvites(r.Context(), req.N)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "invalid invite count") {
				writeErr(w, http.StatusBadRequest, "mint_failed", "invalid invite count")
			} else {
				log.Printf("mint invites failed err=%v", err)
				writeErr(w, http.StatusInternalServerError, "mint_failed", "internal error")
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"invites": codes})
		auditLog(r, "admin.mint_invites", fmt.Sprintf("n=%d", req.N), "ok")
	})

	mux.HandleFunc("/v1/me/account", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
			return
		}
		username, ok := userFromAPIKey(w, r, store)
		if !ok {
			return
		}
		acc, err := store.GetAccount(r.Context(), username)
		if err != nil {
			mapIdentityErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"account": acc})
	})

	mux.HandleFunc("/v1/me/api-key/rotate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
			return
		}
		presented, ok := bearerToken(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "api key required")
			return
		}
		username, newKey, err := store.RotateAPIKey(r.Context(), presented)
		if err != nil {
			mapIdentityErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"username": username, "api_key": newKey})
	})
}

func registerRemainingAPIRoutes(
	mux *http.ServeMux,
	store *identity.Store,
	metrics *appMetrics,
	adminTokens []string,
	adminCIDRs []netip.Prefix,
	maxJSONBytes int64,
) {
	mux.HandleFunc("/v1/admin/accounts/", func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r, adminTokens, adminCIDRs, metrics) {
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/v1/admin/accounts/")
		path = strings.TrimSpace(path)
		if path == "" {
			writeErr(w, http.StatusNotFound, "not_found", "missing username")
			return
		}
		if strings.HasSuffix(path, "/soft-delete") {
			u := strings.TrimSuffix(path, "/soft-delete")
			if r.Method != http.MethodPost {
				writeErr(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
				return
			}
			if err := store.SoftDelete(r.Context(), u); err != nil {
				mapIdentityErr(w, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"username": u, "status": identity.StatusSoftDeleted})
			auditLog(r, "admin.soft_delete", u, "ok")
			return
		}
		if strings.HasSuffix(path, "/restore") {
			u := strings.TrimSuffix(path, "/restore")
			if r.Method != http.MethodPost {
				writeErr(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
				return
			}
			if err := store.Restore(r.Context(), u); err != nil {
				mapIdentityErr(w, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"username": u, "status": identity.StatusActive})
			auditLog(r, "admin.restore", u, "ok")
			return
		}
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
			return
		}
		acc, err := store.GetAccount(r.Context(), path)
		if err != nil {
			mapIdentityErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"account": acc})
	})

	mux.HandleFunc("/v1/admin/messages", func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r, adminTokens, adminCIDRs, metrics) {
			return
		}
		switch r.Method {
		case http.MethodPost:
			var req struct {
				Username   string `json:"username"`
				Alias      string `json:"alias"`
				Sender     string `json:"sender"`
				Ciphertext string `json:"ciphertext"`
				TTLSeconds int    `json:"ttl_seconds"`
			}
			if err := decodeJSON(w, r, &req, maxJSONBytes); err != nil {
				handleDecodeErr(w, err)
				return
			}
			ttl := 15 * time.Minute
			if req.TTLSeconds > 0 {
				ttl = time.Duration(req.TTLSeconds) * time.Second
			}
			msg, err := store.EnqueueCiphertext(r.Context(), req.Username, req.Alias, req.Sender, req.Ciphertext, ttl)
			if err != nil {
				mapIdentityErr(w, err)
				return
			}
			writeJSON(w, http.StatusCreated, map[string]any{"message": msg})
			auditLog(r, "admin.enqueue_message", req.Username, "ok")
		case http.MethodGet:
			u := strings.TrimSpace(r.URL.Query().Get("username"))
			msgs, err := store.ListCiphertext(r.Context(), u, time.Now().UTC(), 200)
			if err != nil {
				mapIdentityErr(w, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"items": msgs})
		default:
			writeErr(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		}
	})

	mux.HandleFunc("/v1/admin/messages/", func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r, adminTokens, adminCIDRs, metrics) {
			return
		}
		if r.Method != http.MethodDelete {
			writeErr(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/v1/admin/messages/")
		parts := strings.Split(strings.TrimSpace(rest), "/")
		if len(parts) != 2 {
			writeErr(w, http.StatusBadRequest, "invalid_request", "expected /v1/admin/messages/{username}/{id}")
			return
		}
		id, err := parseInt64(parts[1])
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "invalid message id")
			return
		}
		if err := store.DeleteMessage(r.Context(), parts[0], id); err != nil {
			mapIdentityErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": id})
		auditLog(r, "admin.delete_message", fmt.Sprintf("%s/%d", parts[0], id), "ok")
	})

	mux.HandleFunc("/v1/admin/purge-expired", func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r, adminTokens, adminCIDRs, metrics) {
			return
		}
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
			return
		}
		n, err := store.PurgeExpired(r.Context(), time.Now().UTC())
		if err != nil {
			log.Printf("purge expired failed err=%v", err)
			writeErr(w, http.StatusInternalServerError, "purge_failed", "internal error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"purged": n})
		auditLog(r, "admin.purge_expired", fmt.Sprintf("purged=%d", n), "ok")
	})

	mux.HandleFunc("/v1/invite-requests", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
			return
		}
		var req struct {
			Email string `json:"email"`
			Note  string `json:"note"`
		}
		if err := decodeJSON(w, r, &req, maxJSONBytes); err != nil {
			handleDecodeErr(w, err)
			return
		}
		ir, err := store.CreateInviteRequest(r.Context(), req.Email, req.Note, sourceBucket(r.RemoteAddr))
		if err != nil {
			mapIdentityErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"request_id": ir.ID,
			"status":     ir.Status,
			"message":    "Invite request received",
		})
	})

	mux.HandleFunc("/v1/admin/invite-requests", func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r, adminTokens, adminCIDRs, metrics) {
			return
		}
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
			return
		}
		status := strings.TrimSpace(r.URL.Query().Get("status"))
		items, err := store.ListInviteRequests(r.Context(), status, 200)
		if err != nil {
			mapIdentityErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	})

	mux.HandleFunc("/v1/admin/invite-requests/", func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r, adminTokens, adminCIDRs, metrics) {
			return
		}
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/v1/admin/invite-requests/")
		if !strings.HasSuffix(rest, "/ack") {
			writeErr(w, http.StatusBadRequest, "invalid_request", "expected /v1/admin/invite-requests/{id}/ack")
			return
		}
		idPart := strings.TrimSuffix(rest, "/ack")
		idPart = strings.Trim(idPart, "/")
		id, err := parseInt64(idPart)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "invalid request id")
			return
		}
		if err := store.AcknowledgeInviteRequest(r.Context(), id); err != nil {
			mapIdentityErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": identity.InviteRequestAcknowledged})
		auditLog(r, "admin.ack_invite_request", fmt.Sprintf("%d", id), "ok")
	})

	mux.HandleFunc("/v1/me/messages", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
			return
		}
		username, ok := userFromAPIKey(w, r, store)
		if !ok {
			return
		}
		msgs, err := store.ListCiphertext(r.Context(), username, time.Now().UTC(), 200)
		if err != nil {
			mapIdentityErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": msgs})
	})

	mux.HandleFunc("/v1/me/messages/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			writeErr(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
			return
		}
		username, ok := userFromAPIKey(w, r, store)
		if !ok {
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/v1/me/messages/")
		id, err := parseInt64(rest)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "invalid message id")
			return
		}
		if err := store.DeleteMessage(r.Context(), username, id); err != nil {
			mapIdentityErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": id})
	})
}

func writeMetrics(w http.ResponseWriter, metrics *appMetrics) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "sisumail_http_requests_total %d\n", metrics.httpRequestsTotal.Load())
	fmt.Fprintf(w, "sisumail_http_errors_total %d\n", metrics.httpErrorsTotal.Load())
	fmt.Fprintf(w, "sisumail_http_auth_failures_total %d\n", metrics.httpAuthFailuresTotal.Load())
	fmt.Fprintf(w, "sisumail_claims_total %d\n", metrics.claimsTotal.Load())
	fmt.Fprintf(w, "sisumail_claim_failures_total %d\n", metrics.claimFailuresTotal.Load())
	fmt.Fprintf(w, "sisumail_smtp_connections_current %d\n", metrics.smtpConnectionsCurrent.Load())
	fmt.Fprintf(w, "sisumail_smtp_connections_total %d\n", metrics.smtpConnectionsTotal.Load())
	fmt.Fprintf(w, "sisumail_smtp_accepted_total %d\n", metrics.smtpAcceptedTotal.Load())
	fmt.Fprintf(w, "sisumail_smtp_rejected_total %d\n", metrics.smtpRejectedTotal.Load())
	fmt.Fprintf(w, "sisumail_purge_removed_total %d\n", metrics.purgeRemovedTotal.Load())
}

func runPurgeWorker(ctx context.Context, store *identity.Store, interval time.Duration, metrics *appMetrics) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			purgeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			n, err := store.PurgeExpired(purgeCtx, now.UTC())
			if err != nil {
				cancel()
				log.Printf("purge worker error: %v", err)
				continue
			}
			if err := store.PurgeRevokedAPIKeys(purgeCtx, now.UTC()); err != nil {
				log.Printf("purge revoked api keys error: %v", err)
			}
			cancel()
			if n > 0 {
				metrics.purgeRemovedTotal.Add(n)
				log.Printf("purge worker removed %d expired messages", n)
			}
		}
	}
}

func dirExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

func serveStaticSite(mux *http.ServeMux, siteDir string) {
	fs := http.FileServer(http.Dir(siteDir))
	mux.Handle("/assets/", fs)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.ServeFile(w, r, filepath.Join(siteDir, "index.html"))
		case "/apply":
			http.ServeFile(w, r, filepath.Join(siteDir, "apply.html"))
		case "/quickstart":
			http.ServeFile(w, r, filepath.Join(siteDir, "quickstart.html"))
		case "/inboxes":
			http.ServeFile(w, r, filepath.Join(siteDir, "inboxes.html"))
		default:
			http.NotFound(w, r)
		}
	})
}
