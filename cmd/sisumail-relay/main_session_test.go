package main

import (
	"testing"
	"time"
)

func TestSessionRequestAllowed(t *testing.T) {
	tests := []struct {
		reqType      string
		wantAllow    bool
		wantExecLike bool
	}{
		{reqType: "shell", wantAllow: true, wantExecLike: false},
		{reqType: "pty-req", wantAllow: true, wantExecLike: false},
		{reqType: "window-change", wantAllow: true, wantExecLike: false},
		{reqType: "exec", wantAllow: false, wantExecLike: true},
		{reqType: "subsystem", wantAllow: false, wantExecLike: true},
		{reqType: "env", wantAllow: false, wantExecLike: false},
		{reqType: "unknown", wantAllow: false, wantExecLike: false},
	}
	for _, tt := range tests {
		gotAllow, gotExec := sessionRequestAllowed(tt.reqType)
		if gotAllow != tt.wantAllow || gotExec != tt.wantExecLike {
			t.Fatalf("sessionRequestAllowed(%q): got (%v,%v) want (%v,%v)", tt.reqType, gotAllow, gotExec, tt.wantAllow, tt.wantExecLike)
		}
	}
}

func TestIsSupportedClientChannelType(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{in: "session", want: true},
		{in: "key-lookup", want: true},
		{in: "chat-send", want: true},
		{in: "acme-dns01", want: true},
		{in: "claim-v1", want: true},
		{in: " chat-send ", want: true},
		{in: "", want: false},
		{in: "spool-delivery", want: false},
		{in: "chat-delivery", want: false},
		{in: "exec", want: false},
		{in: "unknown", want: false},
	}
	for _, tt := range tests {
		if got := isSupportedClientChannelType(tt.in); got != tt.want {
			t.Fatalf("isSupportedClientChannelType(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestParseRelayShellDirective(t *testing.T) {
	tests := []struct {
		in       string
		wantKind string
		wantA    string
		wantB    string
	}{
		{in: "", wantKind: "noop"},
		{in: "hello", wantKind: "unknown", wantA: "hello"},
		{in: "¤help", wantKind: "help"},
		{in: "? chatq", wantKind: "help", wantA: "chatq"},
		{in: "help", wantKind: "help"},
		{in: "¤examples", wantKind: "examples"},
		{in: "examples", wantKind: "examples"},
		{in: "¤x", wantKind: "examples"},
		{in: "/help", wantKind: "help"},
		{in: "¤whoami", wantKind: "whoami"},
		{in: "whoami", wantKind: "whoami"},
		{in: "¤status", wantKind: "status"},
		{in: "stat", wantKind: "status"},
		{in: "status", wantKind: "status"},
		{in: "¤lookup niklas", wantKind: "lookup", wantA: "niklas"},
		{in: "lookup niklas", wantKind: "lookup", wantA: "niklas"},
		{in: "¤chatq", wantKind: "chatq"},
		{in: "chatq --full", wantKind: "chatq", wantA: "--full"},
		{in: "chatq --from alice --since 24h", wantKind: "chatq", wantA: "--from alice --since 24h"},
		{in: "ls", wantKind: "chatq"},
		{in: "chatq", wantKind: "chatq"},
		{in: "chatq read 123", wantKind: "chatq", wantA: "read 123"},
		{in: "chatq ack 123", wantKind: "chatq", wantA: "ack 123"},
		{in: "reply 123 hello", wantKind: "reply", wantA: "123", wantB: "hello"},
		{in: "r 123 hello there", wantKind: "reply", wantA: "123", wantB: "hello there"},
		{in: "¤mailq", wantKind: "mailq"},
		{in: "mailq", wantKind: "mailq"},
		{in: "clear", wantKind: "clear"},
		{in: "/clear", wantKind: "clear"},
		{in: "set compact on", wantKind: "set", wantA: "compact on"},
		{in: "/set compact off", wantKind: "set", wantA: "compact off"},
		{in: "motd off", wantKind: "motd", wantA: "off"},
		{in: "¤quit", wantKind: "quit"},
		{in: "quit", wantKind: "quit"},
		{in: "/whomai", wantKind: "unknown", wantA: "whomai"},
		{in: "¤alice hi there", wantKind: "send", wantA: "alice", wantB: "hi there"},
		{in: "alice hi there", wantKind: "send", wantA: "alice", wantB: "hi there"},
	}
	for _, tt := range tests {
		kind, a, b := parseRelayShellDirective(tt.in)
		if kind != tt.wantKind || a != tt.wantA || b != tt.wantB {
			t.Fatalf("parseRelayShellDirective(%q): got (%q,%q,%q) want (%q,%q,%q)", tt.in, kind, a, b, tt.wantKind, tt.wantA, tt.wantB)
		}
	}
}

func TestParseChatQCommand(t *testing.T) {
	cmd, err := parseChatQCommand("")
	if err != nil || cmd.mode != "list" || cmd.fullTimestamps || cmd.fromUser != "" || cmd.since != 0 {
		t.Fatalf("parseChatQCommand empty: got %+v err=%v", cmd, err)
	}
	cmd, err = parseChatQCommand("--full --from Alice --since 24h")
	if err != nil || !cmd.fullTimestamps || cmd.fromUser != "alice" || cmd.since != 24*time.Hour {
		t.Fatalf("parseChatQCommand list opts: got %+v err=%v", cmd, err)
	}
	cmd, err = parseChatQCommand("read 123")
	if err != nil || cmd.mode != "read" || cmd.id != "123" {
		t.Fatalf("parseChatQCommand read: got %+v err=%v", cmd, err)
	}
	cmd, err = parseChatQCommand("ack 321")
	if err != nil || cmd.mode != "ack" || cmd.id != "321" {
		t.Fatalf("parseChatQCommand ack: got %+v err=%v", cmd, err)
	}
	if _, err := parseChatQCommand("--bad"); err == nil {
		t.Fatal("parseChatQCommand should fail for unknown option")
	}
}

func TestFormatRelativeTime(t *testing.T) {
	now := time.Date(2026, 2, 12, 8, 0, 0, 0, time.UTC)
	if got := formatRelativeTime(now.Add(-30*time.Second), now); got != "30s ago" {
		t.Fatalf("formatRelativeTime seconds: got %q", got)
	}
	if got := formatRelativeTime(now.Add(-5*time.Minute), now); got != "5m ago" {
		t.Fatalf("formatRelativeTime minutes: got %q", got)
	}
	if got := formatRelativeTime(now.Add(-2*time.Hour), now); got != "2h ago" {
		t.Fatalf("formatRelativeTime hours: got %q", got)
	}
	if got := formatRelativeTime(now.Add(2*time.Minute), now); got != "in 2m" {
		t.Fatalf("formatRelativeTime future: got %q", got)
	}
}

func TestSuggestShellCommand(t *testing.T) {
	if got := suggestShellCommand("whomai"); got != "whoami" {
		t.Fatalf("suggestShellCommand whomai: got %q", got)
	}
	if got := suggestShellCommand("statu"); got != "status" {
		t.Fatalf("suggestShellCommand statu: got %q", got)
	}
}

func TestParseSetCommand(t *testing.T) {
	key, val, ok := parseSetCommand("compact on")
	if !ok || key != "compact" || val != "on" {
		t.Fatalf("parseSetCommand compact on: got key=%q val=%q ok=%v", key, val, ok)
	}
	if _, _, ok := parseSetCommand("compact maybe"); ok {
		t.Fatal("parseSetCommand should reject invalid value")
	}
	if _, _, ok := parseSetCommand("theme on"); ok {
		t.Fatal("parseSetCommand should reject unknown key")
	}
}

func TestParseSinceDuration(t *testing.T) {
	d, err := parseSinceDuration("7d")
	if err != nil || d != 7*24*time.Hour {
		t.Fatalf("parseSinceDuration 7d: got %v err=%v", d, err)
	}
	d, err = parseSinceDuration("90m")
	if err != nil || d != 90*time.Minute {
		t.Fatalf("parseSinceDuration 90m: got %v err=%v", d, err)
	}
	if _, err := parseSinceDuration("-1h"); err == nil {
		t.Fatal("parseSinceDuration should reject negative")
	}
}
