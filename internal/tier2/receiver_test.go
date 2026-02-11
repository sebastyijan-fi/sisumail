package tier2

import (
	"strings"
	"testing"
	"time"

	gosmtp "github.com/emersion/go-smtp"
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

func TestReceiverRequiresTLS(t *testing.T) {
	pub, _ := genTestKeyPair(t)

	rcv := &Receiver{
		KeyResolver: &staticResolver{domain: "niklas.sisumail.fi", key: pub},
		Spool:       &FileSpool{Root: t.TempDir()},
		Domain:      "sisumail.fi",
		RequireTLS:  true,
	}

	sessAny, err := rcv.NewSession(nil)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	sess := sessAny.(*session)

	err = sess.Mail("sender@example.com", nil)
	if err == nil {
		t.Fatal("expected TLS-required error")
	}

	smtpErr, ok := err.(*gosmtp.SMTPError)
	if !ok {
		t.Fatalf("expected SMTPError, got %T", err)
	}
	if smtpErr.Code != 530 {
		t.Fatalf("expected SMTP 530, got %d", smtpErr.Code)
	}
}

func TestReceiverRateLimitsMessagesBySource(t *testing.T) {
	pub, _ := genTestKeyPair(t)
	spool := &FileSpool{Root: t.TempDir()}
	guard := NewSourceGuard(10, 1, nil)
	rcv := &Receiver{
		KeyResolver: &staticResolver{domain: "niklas.sisumail.fi", key: pub},
		Spool:       spool,
		Domain:      "sisumail.fi",
		Guard:       guard,
	}

	sessAny, err := rcv.NewSession(nil)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	sess := sessAny.(*session)
	defer sess.Logout()

	if err := sess.Mail("sender@example.com", nil); err != nil {
		t.Fatalf("Mail: %v", err)
	}
	if err := sess.Rcpt("mail@niklas.sisumail.fi", nil); err != nil {
		t.Fatalf("Rcpt: %v", err)
	}
	if err := sess.Data(strings.NewReader("Subject: 1\r\n\r\nok\r\n")); err != nil {
		t.Fatalf("Data(1): %v", err)
	}
	err = sess.Data(strings.NewReader("Subject: 2\r\n\r\nblocked\r\n"))
	if err == nil {
		t.Fatal("expected second DATA to be rate-limited")
	}
	smtpErr, ok := err.(*gosmtp.SMTPError)
	if !ok {
		t.Fatalf("expected SMTPError, got %T", err)
	}
	if smtpErr.Code != 451 {
		t.Fatalf("expected SMTP 451, got %d", smtpErr.Code)
	}
}

func TestReceiverReleasesConnBudgetOnLogout(t *testing.T) {
	pub, _ := genTestKeyPair(t)
	guard := NewSourceGuard(1, 10, nil)
	rcv := &Receiver{
		KeyResolver: &staticResolver{domain: "niklas.sisumail.fi", key: pub},
		Spool:       &FileSpool{Root: t.TempDir()},
		Domain:      "sisumail.fi",
		Guard:       guard,
	}

	s1Any, err := rcv.NewSession(nil)
	if err != nil {
		t.Fatalf("NewSession(1): %v", err)
	}
	s1 := s1Any.(*session)
	_, err = rcv.NewSession(nil)
	if err == nil {
		t.Fatal("expected second session to be blocked by conn cap")
	}
	smtpErr, ok := err.(*gosmtp.SMTPError)
	if !ok || smtpErr.Code != 421 {
		t.Fatalf("expected SMTP 421, got %v (%T)", err, err)
	}
	if err := s1.Logout(); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := rcv.NewSession(nil); err != nil {
		t.Fatalf("expected new session after logout, got: %v", err)
	}
}
