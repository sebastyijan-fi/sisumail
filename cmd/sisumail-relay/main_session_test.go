package main

import "testing"

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

func TestParseRelayShellDirective(t *testing.T) {
	tests := []struct {
		in       string
		wantKind string
		wantA    string
		wantB    string
	}{
		{in: "", wantKind: "noop"},
		{in: "hello", wantKind: "unknown"},
		{in: "¤help", wantKind: "help"},
		{in: "¤examples", wantKind: "examples"},
		{in: "¤x", wantKind: "examples"},
		{in: "/help", wantKind: "help"},
		{in: "¤whoami", wantKind: "whoami"},
		{in: "¤status", wantKind: "status"},
		{in: "¤lookup niklas", wantKind: "lookup", wantA: "niklas"},
		{in: "¤chatq", wantKind: "chatq"},
		{in: "¤mailq", wantKind: "mailq"},
		{in: "¤quit", wantKind: "quit"},
		{in: "¤alice hi there", wantKind: "send", wantA: "alice", wantB: "hi there"},
	}
	for _, tt := range tests {
		kind, a, b := parseRelayShellDirective(tt.in)
		if kind != tt.wantKind || a != tt.wantA || b != tt.wantB {
			t.Fatalf("parseRelayShellDirective(%q): got (%q,%q,%q) want (%q,%q,%q)", tt.in, kind, a, b, tt.wantKind, tt.wantA, tt.wantB)
		}
	}
}
