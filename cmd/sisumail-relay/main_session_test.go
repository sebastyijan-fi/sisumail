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
