package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseAdminTokens(t *testing.T) {
	got := parseAdminTokens(" a ,b,a,, c ")
	if len(got) != 3 {
		t.Fatalf("expected 3 tokens, got %d", len(got))
	}
	if got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("unexpected tokens: %#v", got)
	}
}

func TestIsValidAdminToken(t *testing.T) {
	tokens := []string{"alpha", "beta"}
	if !isValidAdminToken("alpha", tokens) {
		t.Fatal("expected alpha valid")
	}
	if isValidAdminToken("gamma", tokens) {
		t.Fatal("expected gamma invalid")
	}
	if isValidAdminToken("", tokens) {
		t.Fatal("expected empty invalid")
	}
}

func TestDecodeJSONLimit(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"a":"1234567890"}`))
	w := httptest.NewRecorder()
	var out map[string]string
	err := decodeJSON(w, req, &out, 8)
	if err == nil {
		t.Fatal("expected size limit error")
	}
	handleDecodeErr(w, err)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", w.Code)
	}
}
