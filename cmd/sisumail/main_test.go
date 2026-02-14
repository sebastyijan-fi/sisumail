package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gosmtp "github.com/emersion/go-smtp"
	"github.com/sisumail/sisumail/internal/core"
	"github.com/sisumail/sisumail/internal/proto"
	"github.com/sisumail/sisumail/internal/tlsboot"
)

func TestInjectSisumailHeaders(t *testing.T) {
	in := []byte("From: a@example.com\r\nSubject: hello\r\n\r\nbody\r\n")
	out := injectSisumailHeaders(in, map[string]string{
		"X-Sisumail-Tier": "tier1",
	})
	s := string(out)
	if !strings.Contains(s, "X-Sisumail-Tier: tier1\r\n\r\nbody") {
		t.Fatalf("expected injected header, got: %q", s)
	}
}

func TestInjectSisumailHeaders_LFOnly(t *testing.T) {
	in := []byte("From: a@example.com\nSubject: hello\n\nbody\n")
	out := injectSisumailHeaders(in, map[string]string{
		"X-Sisumail-Tier": "tier1",
	})
	s := string(out)
	if !strings.Contains(s, "Subject: hello\nX-Sisumail-Tier: tier1\n\nbody") {
		t.Fatalf("expected injected header with LF separator, got: %q", s)
	}
}

func TestDeliveryMetaBridgeTakeOnce(t *testing.T) {
	b := newDeliveryMetaBridge()
	meta := proto.SMTPDeliveryMeta{
		SenderPort: 25,
		ReceivedAt: time.Now(),
	}
	b.Put("127.0.0.1:1234", meta)

	got, ok := b.Take("127.0.0.1:1234")
	if !ok {
		t.Fatal("expected metadata")
	}
	if got.SenderPort != 25 {
		t.Fatalf("unexpected sender port: %d", got.SenderPort)
	}
	if _, ok := b.Take("127.0.0.1:1234"); ok {
		t.Fatal("expected one-shot metadata consumption")
	}
}

func TestTierBadge(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "tier1", want: "Tier1 Blind"},
		{in: "tier2", want: "Tier2 Spool"},
		{in: "", want: "Unknown"},
		{in: "custom", want: "custom"},
	}
	for _, tc := range cases {
		if got := tierBadge(tc.in); got != tc.want {
			t.Fatalf("tierBadge(%q): got %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestApplyInboxFilter(t *testing.T) {
	entries := []core.MaildirEntry{
		{ID: "1", Tier: "tier1", Seen: false},
		{ID: "2", Tier: "tier2", Seen: false},
		{ID: "3", Tier: "tier1", Seen: true},
	}

	if got := applyInboxFilter(entries, inboxFilterAll); len(got) != 3 {
		t.Fatalf("all: got %d, want 3", len(got))
	}
	if got := applyInboxFilter(entries, inboxFilterTier1); len(got) != 2 {
		t.Fatalf("tier1: got %d, want 2", len(got))
	}
	if got := applyInboxFilter(entries, inboxFilterTier2); len(got) != 1 {
		t.Fatalf("tier2: got %d, want 1", len(got))
	}
	if got := applyInboxFilter(entries, inboxFilterUnread); len(got) != 2 {
		t.Fatalf("unread: got %d, want 2", len(got))
	}
}

func TestApplySearchRows(t *testing.T) {
	rows := []inboxRow{
		{Entry: core.MaildirEntry{ID: "id-1"}, From: "alice@example.com", Subject: "hello"},
		{Entry: core.MaildirEntry{ID: "id-2"}, From: "bob@example.com", Subject: "status"},
	}

	if got := applySearchRows(rows, "alice"); len(got) != 1 {
		t.Fatalf("search alice: got %d, want 1", len(got))
	}
	if got := applySearchRows(rows, "ID-2"); len(got) != 1 {
		t.Fatalf("search id-2: got %d, want 1", len(got))
	}
	if got := applySearchRows(rows, ""); len(got) != 2 {
		t.Fatalf("search empty: got %d, want 2", len(got))
	}
}

func TestPaginateRows(t *testing.T) {
	rows := make([]inboxRow, 0, 5)
	for i := 0; i < 5; i++ {
		rows = append(rows, inboxRow{Entry: core.MaildirEntry{ID: string(rune('a' + i))}})
	}

	page1, total := paginateRows(rows, 1, 2)
	if total != 3 || len(page1) != 2 {
		t.Fatalf("page1: total=%d len=%d", total, len(page1))
	}
	page3, total := paginateRows(rows, 3, 2)
	if total != 3 || len(page3) != 1 {
		t.Fatalf("page3: total=%d len=%d", total, len(page3))
	}
}

func TestTrustSummary(t *testing.T) {
	h1 := mail.Header{}
	h1["X-Sisumail-Sender-Ip"] = []string{"1.2.3.4"}
	h1["X-Sisumail-Received-At"] = []string{"2026-02-11T00:00:00Z"}
	if got := trustSummary("tier1", h1); got != "blind+meta" {
		t.Fatalf("tier1 meta: got %q", got)
	}

	h2 := mail.Header{}
	h2["X-Sisumail-Spool-Message-Id"] = []string{"abc"}
	h2["X-Sisumail-Spool-Size"] = []string{"123"}
	if got := trustSummary("tier2", h2); got != "spool+proof" {
		t.Fatalf("tier2 proof: got %q", got)
	}

	if got := trustSummary("tier1", nil); got != "blind+nometa" {
		t.Fatalf("tier1 none: got %q", got)
	}
	if got := trustSummary("tier2", nil); got != "spool+noproof" {
		t.Fatalf("tier2 none: got %q", got)
	}
}

func TestParseChatSendCommand(t *testing.T) {
	peer, msg, ok := parseChatSendCommand("c bob hello world")
	if !ok || peer != "bob" || msg != "hello world" {
		t.Fatalf("parse failed: ok=%v peer=%q msg=%q", ok, peer, msg)
	}
	if _, _, ok := parseChatSendCommand("c bob"); ok {
		t.Fatal("expected parse failure without message")
	}
	if _, _, ok := parseChatSendCommand("c "); ok {
		t.Fatal("expected parse failure with empty command")
	}
}

func TestTLSCertStateSetIfChanged(t *testing.T) {
	c1, err := tlsboot.SelfSigned([]string{"a.example"}, time.Hour)
	if err != nil {
		t.Fatalf("SelfSigned c1: %v", err)
	}
	c2, err := tlsboot.SelfSigned([]string{"b.example"}, time.Hour)
	if err != nil {
		t.Fatalf("SelfSigned c2: %v", err)
	}
	s := newTLSCertState(c1)
	if s.SetIfChanged(c1) {
		t.Fatal("expected unchanged certificate to be ignored")
	}
	if !s.SetIfChanged(c2) {
		t.Fatal("expected changed certificate to be accepted")
	}
	got := s.Get()
	if got == nil || len(got.Certificate) == 0 {
		t.Fatal("expected current certificate")
	}
}

func TestLoadHCloudTokenPrefersPrimaryVar(t *testing.T) {
	t.Setenv("HCLOUD_TOKEN", "primary")
	t.Setenv("HETZNER_CLOUD_TOKEN", "fallback")
	if got := loadHCloudToken(); got != "primary" {
		t.Fatalf("loadHCloudToken got %q, want primary", got)
	}
}

func TestParseShellDirective(t *testing.T) {
	cases := []struct {
		in       string
		wantKind string
		wantArg1 string
		wantArg2 string
	}{
		{in: "", wantKind: "noop"},
		{in: "¤help", wantKind: "help"},
		{in: "/help", wantKind: "help"},
		{in: "¤whoami", wantKind: "whoami"},
		{in: "¤inbox", wantKind: "inbox"},
		{in: "¤read abc123", wantKind: "read", wantArg1: "abc123"},
		{in: "¤history niklas", wantKind: "history", wantArg1: "niklas"},
		{in: "¤niklas hello there", wantKind: "send", wantArg1: "niklas", wantArg2: "hello there"},
		{in: "plain text", wantKind: "unknown"},
	}
	for _, tc := range cases {
		k, a, b := parseShellDirective(tc.in)
		if k != tc.wantKind || a != tc.wantArg1 || b != tc.wantArg2 {
			t.Fatalf("parseShellDirective(%q): got (%q,%q,%q) want (%q,%q,%q)", tc.in, k, a, b, tc.wantKind, tc.wantArg1, tc.wantArg2)
		}
	}
}

func TestBuildHostKeyCallbackInsecure(t *testing.T) {
	cb, err := buildHostKeyCallback(true, "")
	if err != nil {
		t.Fatalf("buildHostKeyCallback insecure: %v", err)
	}
	if cb == nil {
		t.Fatal("expected callback")
	}
}

func TestBuildHostKeyCallbackMissingFile(t *testing.T) {
	_, err := buildHostKeyCallback(false, "/nonexistent/known_hosts")
	if err == nil {
		t.Fatal("expected error for missing known_hosts")
	}
}

func TestRelayControlUnavailableDetectors(t *testing.T) {
	errUnknown := errors.New("ssh: rejected: unknown channel type (unsupported)")
	errUnsupported := errors.New("unsupported operation")
	errOther := errors.New("dial timeout")

	if !isUnsupportedChannelError(errUnknown) || !isRelayACMEControlUnavailable(errUnknown) || !isRelayChatControlUnavailable(errUnknown) {
		t.Fatal("expected unknown channel error to be detected as unsupported relay control channel")
	}
	if !isUnsupportedChannelError(errUnsupported) {
		t.Fatal("expected unsupported operation to be detected")
	}
	if isUnsupportedChannelError(errOther) || isRelayACMEControlUnavailable(errOther) || isRelayChatControlUnavailable(errOther) {
		t.Fatal("unexpected unsupported-channel detection on unrelated error")
	}
}

func TestNormalizeChatSendError(t *testing.T) {
	err := normalizeChatSendError(errors.New("ssh: rejected: unknown channel type (unsupported)"))
	if err == nil {
		t.Fatal("expected normalized error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "relay chat channel unavailable") {
		t.Fatalf("expected user-facing chat channel message, got %q", err.Error())
	}
}

func TestApplyConfigOverrides(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.env")
	err := os.WriteFile(cfgPath, []byte("user=fromcfg\nshell=true\n"), 0600)
	if err != nil {
		t.Fatalf("write config: %v", err)
	}

	user := "default"
	shell := false
	explicit := map[string]bool{"shell": true}
	err = applyConfigOverrides(cfgPath, explicit, map[string]configField{
		"user":  {FlagName: "user", Set: setString(&user)},
		"shell": {FlagName: "shell", Set: setBool(&shell)},
	})
	if err != nil {
		t.Fatalf("applyConfigOverrides: %v", err)
	}
	if user != "fromcfg" {
		t.Fatalf("user override: got %q want fromcfg", user)
	}
	if shell {
		t.Fatal("shell should not be overridden when explicit flag is set")
	}
}

func TestWriteCoreConfigAndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sisumail", "config.env")
	err := writeCoreConfig(path, coreConfigValues{
		Relay:      "sisumail.fi:2222",
		User:       "niklas",
		Zone:       "sisumail.fi",
		Key:        "/home/me/.ssh/id_ed25519",
		KnownHosts: "/home/me/.ssh/known_hosts",
	})
	if err != nil {
		t.Fatalf("writeCoreConfig: %v", err)
	}
	values, err := readConfigFile(path)
	if err != nil {
		t.Fatalf("readConfigFile: %v", err)
	}
	if values["relay"] != "sisumail.fi:2222" || values["user"] != "niklas" {
		t.Fatalf("unexpected config values: %#v", values)
	}
}

func TestEnsureSSHKeyMaterialCreatesPair(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	created, err := ensureSSHKeyMaterial(keyPath, "alice")
	if err != nil {
		t.Fatalf("ensureSSHKeyMaterial: %v", err)
	}
	if !created {
		t.Fatal("expected key to be created")
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("missing private key: %v", err)
	}
	pub := keyPath + ".pub"
	b, err := os.ReadFile(pub)
	if err != nil {
		t.Fatalf("missing public key: %v", err)
	}
	if !strings.HasPrefix(string(b), "ssh-ed25519 ") {
		t.Fatalf("unexpected pubkey format: %q", string(b))
	}
}

func TestEnsureSSHKeyMaterialCreatesMissingPublicKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	if _, err := ensureSSHKeyMaterial(keyPath, "alice"); err != nil {
		t.Fatalf("initial key create: %v", err)
	}
	if err := os.Remove(keyPath + ".pub"); err != nil {
		t.Fatalf("remove pubkey: %v", err)
	}
	created, err := ensureSSHKeyMaterial(keyPath, "alice")
	if err != nil {
		t.Fatalf("ensureSSHKeyMaterial second run: %v", err)
	}
	if created {
		t.Fatal("expected private key to be reused")
	}
	if _, err := os.Stat(keyPath + ".pub"); err != nil {
		t.Fatalf("missing regenerated pubkey: %v", err)
	}
}

func TestEnsureFileExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	created, err := ensureFileExists(path, 0600)
	if err != nil {
		t.Fatalf("ensureFileExists first: %v", err)
	}
	if !created {
		t.Fatal("expected file to be created")
	}
	created, err = ensureFileExists(path, 0600)
	if err != nil {
		t.Fatalf("ensureFileExists second: %v", err)
	}
	if created {
		t.Fatal("expected existing file to be reused")
	}
}

func TestEnsureLocalAPIToken(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "api-token")
	tok1, created, err := ensureLocalAPIToken(p)
	if err != nil {
		t.Fatalf("ensureLocalAPIToken first: %v", err)
	}
	if !created {
		t.Fatal("expected token file to be created")
	}
	if len(tok1) < 32 {
		t.Fatalf("token too short: %q", tok1)
	}
	tok2, created, err := ensureLocalAPIToken(p)
	if err != nil {
		t.Fatalf("ensureLocalAPIToken second: %v", err)
	}
	if created {
		t.Fatal("expected existing token to be reused")
	}
	if tok2 != tok1 {
		t.Fatalf("token changed: %q != %q", tok2, tok1)
	}
}

func TestWithBearerToken(t *testing.T) {
	h := withBearerToken("secret", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req1 := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", rec1.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	req2.Header.Set("Authorization", "Bearer secret")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("expected 204 with auth, got %d", rec2.Code)
	}
}

func TestAliasFromAddress(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"inbox@niklas.sisumail.fi", "inbox"},
		{"Steam@niklas.sisumail.fi", "steam"},
		{"Nik <alerts+bank@niklas.sisumail.fi>", "alerts+bank"},
		{"bad", ""},
	}
	for _, tc := range cases {
		if got := aliasFromAddress(tc.in); got != tc.want {
			t.Fatalf("aliasFromAddress(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestAliasFromAddressRejectsMalformedAliases(t *testing.T) {
	cases := []string{
		"st eam@niklas.sisumail.fi",
		"steam\x00@niklas.sisumail.fi",
		"steam@",
		"steam💣@niklas.sisumail.fi",
	}
	for _, in := range cases {
		if got := aliasFromAddress(in); got != "" {
			t.Fatalf("aliasFromAddress(%q) = %q, want empty", in, got)
		}
	}
}

func TestAliasFromMessageHeadersIgnoresInvalidAndKeepsInjectedFirst(t *testing.T) {
	h := mail.Header{}
	h["X-Sisumail-Alias"] = []string{"inbox", "spoofed"}
	h["Delivered-To"] = []string{"bank@niklas.sisumail.fi"}
	if got := aliasFromMessageHeaders(h); got != "inbox" {
		t.Fatalf("expected first injected alias to win, got %q", got)
	}

	h2 := mail.Header{}
	h2["X-Sisumail-Alias"] = []string{"bad<script>"}
	h2["Delivered-To"] = []string{"bank@niklas.sisumail.fi"}
	if got := aliasFromMessageHeaders(h2); got != "bank" {
		t.Fatalf("expected fallback alias from Delivered-To, got %q", got)
	}
}

func TestLocalInboxAppUsesSafeTextRendering(t *testing.T) {
	if !strings.Contains(localInboxAppHTML, "esc(m.subject") {
		t.Fatal("expected inbox list rendering to escape subject")
	}
	if !strings.Contains(localInboxAppHTML, "esc(m.from") {
		t.Fatal("expected inbox list rendering to escape from")
	}
	if !strings.Contains(localInboxAppHTML, "msgView.textContent = out +") {
		t.Fatal("expected message view to render with textContent")
	}
	if strings.Contains(localInboxAppHTML, "msgView.innerHTML =") {
		t.Fatal("message view must not render via innerHTML")
	}
}

func TestLocalChatAppShowsRelayChannelGuidance(t *testing.T) {
	if !strings.Contains(localChatAppHTML, "relay chat channel unavailable") {
		t.Fatal("expected chat app to surface relay channel unavailable guidance")
	}
}

func TestLocalSessionRcptBlockedAliasLooksLikeInvalidRecipient(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "alias_policy.json")
	policy := newAliasPolicyStore(p)
	if err := policy.Init(); err != nil {
		t.Fatalf("init alias policy: %v", err)
	}
	if err := policy.Block("steam"); err != nil {
		t.Fatalf("block alias: %v", err)
	}

	s := &localSession{isTLS: true, aliases: policy}
	blockedErr := s.Rcpt("steam@niklas.sisumail.fi", nil)
	invalidErr := s.Rcpt("bad", nil)
	if blockedErr == nil || invalidErr == nil {
		t.Fatal("expected both blocked and invalid recipient errors")
	}
	be, ok := blockedErr.(*gosmtp.SMTPError)
	if !ok {
		t.Fatalf("blocked error type: %T", blockedErr)
	}
	ie, ok := invalidErr.(*gosmtp.SMTPError)
	if !ok {
		t.Fatalf("invalid error type: %T", invalidErr)
	}
	if be.Code != 550 || ie.Code != 550 {
		t.Fatalf("expected SMTP 550 for both, got blocked=%d invalid=%d", be.Code, ie.Code)
	}
	if be.Message != ie.Message {
		t.Fatalf("response leak: blocked=%q invalid=%q", be.Message, ie.Message)
	}
}

func TestSpoolReplayGuardSeenOrMark(t *testing.T) {
	g := newSpoolReplayGuard(4, time.Hour)
	now := time.Now()
	if g.SeenOrMark("msg-1", now) {
		t.Fatal("first-seen message must not be flagged as replay")
	}
	if !g.SeenOrMark("msg-1", now.Add(5*time.Minute)) {
		t.Fatal("same message ID within ttl should be flagged as replay")
	}
	if g.SeenOrMark("msg-1", now.Add(2*time.Hour)) {
		t.Fatal("expired replay window should allow message again")
	}
}

func TestLocalSMTPMaxMessageBytesLimit(t *testing.T) {
	const hardCap = 5 << 20
	if localSMTPMaxMessageBytes <= 0 {
		t.Fatalf("localSMTPMaxMessageBytes must be positive, got %d", localSMTPMaxMessageBytes)
	}
	if localSMTPMaxMessageBytes > hardCap {
		t.Fatalf("localSMTPMaxMessageBytes exceeds hard cap: got %d cap %d", localSMTPMaxMessageBytes, hardCap)
	}
}

func TestAliasPolicyStoreBlockUnblock(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "alias_policy.json")
	s := newAliasPolicyStore(p)
	if err := s.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := s.Block("steam"); err != nil {
		t.Fatalf("block: %v", err)
	}
	if !s.IsBlocked("steam") {
		t.Fatal("expected steam blocked")
	}
	s2 := newAliasPolicyStore(p)
	if err := s2.Init(); err != nil {
		t.Fatalf("init reload: %v", err)
	}
	if !s2.IsBlocked("steam") {
		t.Fatal("expected steam blocked after reload")
	}
	if err := s2.Unblock("steam"); err != nil {
		t.Fatalf("unblock: %v", err)
	}
	if s2.IsBlocked("steam") {
		t.Fatal("expected steam unblocked")
	}
}
