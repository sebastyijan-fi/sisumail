package main

import "testing"

func TestParseTLSMode(t *testing.T) {
	tests := []struct {
		in      string
		want    tlsModeKind
		wantErr bool
	}{
		{in: "disable", want: tlsModeDisable},
		{in: "opportunistic", want: tlsModeOpportunistic},
		{in: "required", want: tlsModeRequired},
		{in: " Required ", want: tlsModeRequired},
		{in: "", wantErr: true},
		{in: "strict", wantErr: true},
	}

	for _, tt := range tests {
		got, err := parseTLSMode(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("parseTLSMode(%q): expected error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseTLSMode(%q): %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("parseTLSMode(%q): got %q, want %q", tt.in, got, tt.want)
		}
	}
}
