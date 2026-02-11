// Package tier2 implements the Tier 2 "encrypted spool" SMTP receiver.
//
// Per whitepaper §12, the receiver terminates SMTP/TLS, stream-encrypts the
// full RFC 5322 message to the recipient's SSH key (via age), and writes
// ciphertext + metadata to the spool. Plaintext is never buffered in full
// or persisted to disk.
package tier2

import (
	"fmt"
	"io"
	"strings"
	"time"

	gosmtp "github.com/emersion/go-smtp"

	"github.com/sisumail/sisumail/internal/core"
)

// Receiver is a go-smtp Backend that encrypts messages on ingest.
type Receiver struct {
	KeyResolver core.KeyResolver
	Spool       core.SpoolStore
	Domain      string // e.g. "sisumail.fi"
	MaxSize     int64  // max message size in bytes (0 = no limit)
	RequireTLS  bool   // require STARTTLS before MAIL/RCPT/DATA
}

// NewSession implements smtp.Backend.
func (r *Receiver) NewSession(conn *gosmtp.Conn) (gosmtp.Session, error) {
	return &session{receiver: r, conn: conn}, nil
}

type session struct {
	receiver  *Receiver
	conn      *gosmtp.Conn
	from      string
	recipient string // the first RCPT TO domain
	pubKey    string
}

func (s *session) tlsActive() bool {
	if s.conn == nil {
		return false
	}
	_, ok := s.conn.TLSConnectionState()
	return ok
}

func (s *session) requireTLS() error {
	if !s.receiver.RequireTLS || s.tlsActive() {
		return nil
	}
	return &gosmtp.SMTPError{
		Code:         530,
		EnhancedCode: gosmtp.EnhancedCode{5, 7, 0},
		Message:      "Must issue STARTTLS first",
	}
}

func (s *session) AuthPlain(username, password string) error {
	return gosmtp.ErrAuthUnsupported
}

func (s *session) Mail(from string, opts *gosmtp.MailOptions) error {
	if err := s.requireTLS(); err != nil {
		return err
	}
	s.from = from
	return nil
}

func (s *session) Rcpt(to string, opts *gosmtp.RcptOptions) error {
	if err := s.requireTLS(); err != nil {
		return err
	}

	// Extract domain from RCPT TO for key lookup.
	parts := strings.SplitN(to, "@", 2)
	if len(parts) != 2 {
		return &gosmtp.SMTPError{
			Code:         550,
			EnhancedCode: gosmtp.EnhancedCode{5, 1, 1},
			Message:      "invalid recipient",
		}
	}
	domain := parts[1]

	// Validate that this domain belongs to our root.
	if s.receiver.Domain != "" {
		suffix := "." + s.receiver.Domain
		if !strings.HasSuffix(domain, suffix) {
			return &gosmtp.SMTPError{
				Code:         550,
				EnhancedCode: gosmtp.EnhancedCode{5, 1, 1},
				Message:      "unknown recipient domain",
			}
		}
		// Reject weird domains like ".sisumail.fi".
		if strings.TrimSuffix(domain, suffix) == "" {
			return &gosmtp.SMTPError{
				Code:         550,
				EnhancedCode: gosmtp.EnhancedCode{5, 1, 1},
				Message:      "invalid recipient domain",
			}
		}
	}

	// Look up recipient key.
	key, err := s.receiver.KeyResolver.Resolve(domain)
	if err != nil {
		return &gosmtp.SMTPError{
			Code:         550,
			EnhancedCode: gosmtp.EnhancedCode{5, 1, 1},
			Message:      fmt.Sprintf("unknown recipient domain: %s", domain),
		}
	}
	s.recipient = domain
	s.pubKey = key
	return nil
}

func (s *session) Data(r io.Reader) error {
	if err := s.requireTLS(); err != nil {
		return err
	}

	if s.pubKey == "" {
		return &gosmtp.SMTPError{
			Code:         503,
			EnhancedCode: gosmtp.EnhancedCode{5, 5, 1},
			Message:      "no recipient set",
		}
	}

	// Generate a unique message ID.
	msgID := fmt.Sprintf("%d", time.Now().UnixNano())

	// Extract username from domain (e.g. "niklas.sisumail.fi" → "niklas").
	user := strings.TrimSuffix(s.recipient, "."+s.receiver.Domain)

	// Stream-encrypt: pipe SMTP DATA through age encryption into the spool.
	// The SpoolStore.Put receives a streaming ciphertext reader.
	pr, pw := io.Pipe()

	errCh := make(chan error, 1)
	go func() {
		defer pw.Close()
		// Use StreamEncrypt so Tier 2 always uses the SSH recipient scheme.
		if err := StreamEncrypt(pw, r, s.pubKey); err != nil {
			_ = pw.CloseWithError(err)
			errCh <- err
			return
		}
		errCh <- nil
	}()

	meta := core.SpoolMeta{
		MessageID:  msgID,
		Recipient:  s.recipient,
		ReceivedAt: time.Now(),
		Tier:       "tier2",
	}

	if err := s.receiver.Spool.Put(user, msgID, pr, meta); err != nil {
		return fmt.Errorf("spool put: %w", err)
	}

	// Wait for encryption goroutine.
	if err := <-errCh; err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	return nil
}

func (s *session) Reset() {
	s.from = ""
	s.recipient = ""
	s.pubKey = ""
}

func (s *session) Logout() error {
	return nil
}
