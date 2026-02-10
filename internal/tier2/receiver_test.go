package tier2

import (
	"strings"
	"testing"
	"time"
)

type staticResolver struct {
	domain string
	key    string
}

func (r *staticResolver) Resolve(domain string) (string, error) {
	if domain != r.domain {
		return "", coreErr("not found")
	}
	return r.key, nil
}

type coreErr string

func (e coreErr) Error() string { return string(e) }

func TestReceiverEncryptsAndSpools(t *testing.T) {
	pub, priv := genTestKeyPair(t)

	spool := &FileSpool{Root: t.TempDir()}
	rcv := &Receiver{
		KeyResolver: &staticResolver{domain: "niklas.sisumail.fi", key: pub},
		Spool:       spool,
		Domain:      "sisumail.fi",
	}

	sessAny, err := rcv.NewSession(nil)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	sess := sessAny.(*session)

	if err := sess.Mail("sender@example.com", nil); err != nil {
		t.Fatalf("Mail: %v", err)
	}
	// Include +tag; Tier 2 routes by domain and preserves full message inside ciphertext.
	if err := sess.Rcpt("mail+steam@niklas.sisumail.fi", nil); err != nil {
		t.Fatalf("Rcpt: %v", err)
	}

	plaintext := "From: sender@example.com\r\nSubject: Test\r\n\r\nHello.\r\n"
	if err := sess.Data(strings.NewReader(plaintext)); err != nil {
		t.Fatalf("Data: %v", err)
	}

	// Ensure something was spooled.
	list, err := spool.List("niklas")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(list))
	}
	if list[0].Recipient != "niklas.sisumail.fi" {
		t.Fatalf("recipient meta mismatch: %q", list[0].Recipient)
	}
	if list[0].Tier != "tier2" {
		t.Fatalf("tier meta mismatch: %q", list[0].Tier)
	}
	if list[0].ReceivedAt.After(time.Now().Add(5 * time.Second)) {
		t.Fatalf("received_at looks wrong: %v", list[0].ReceivedAt)
	}

	rc, _, err := spool.Get("niklas", list[0].MessageID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer rc.Close()

	var out strings.Builder
	if err := StreamDecrypt(&out, rc, priv); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if out.String() != plaintext {
		t.Fatalf("plaintext mismatch:\n  got:  %q\n  want: %q", out.String(), plaintext)
	}
}
