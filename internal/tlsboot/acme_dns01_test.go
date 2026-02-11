package tlsboot

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestMergeTXTValues(t *testing.T) {
	got := mergeTXTValues([]string{`"abc"`, "def", `"abc"`}, `"xyz"`)
	want := []string{`"abc"`, `"def"`, `"xyz"`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeTXTValues mismatch:\n got=%v\nwant=%v", got, want)
	}
}

func TestRemoveTXTValue(t *testing.T) {
	got := removeTXTValue([]string{`"abc"`, "def", `"ghi"`}, "def")
	want := []string{`"abc"`, `"ghi"`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("removeTXTValue mismatch:\n got=%v\nwant=%v", got, want)
	}
}

func TestLoadOrCreateAccountKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acct.pem")
	k1, err := loadOrCreateAccountKey(path)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	k2, err := loadOrCreateAccountKey(path)
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	if k1.X.Cmp(k2.X) != 0 || k1.Y.Cmp(k2.Y) != 0 {
		t.Fatal("loaded key does not match stored key")
	}
}
