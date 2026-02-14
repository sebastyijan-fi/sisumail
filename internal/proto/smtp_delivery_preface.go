package proto

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// SMTP delivery channel preface.
//
// This is sent out-of-band, before the raw SMTP-bytes stream, and must not be
// injected into the SMTP stream itself.
//
// Format (single line, LF-terminated):
//   SISUMAIL1 SMTP <sender_ip> <sender_port> <dest_ip> <received_at_unix_ms>\n
//
// After this line, the channel becomes a raw bidirectional byte stream that
// mirrors the sender<->server TCP connection.

const smtpPrefaceMagic = "SISUMAIL1 SMTP"

type SMTPDeliveryMeta struct {
	SenderIP   net.IP
	SenderPort int
	DestIP     net.IP
	ReceivedAt time.Time
}

func WriteSMTPDeliveryPreface(w io.Writer, m SMTPDeliveryMeta) error {
	if m.SenderIP == nil || m.DestIP == nil {
		return fmt.Errorf("missing sender or dest ip")
	}
	if m.SenderPort <= 0 || m.SenderPort > 65535 {
		return fmt.Errorf("invalid sender port")
	}
	ms := m.ReceivedAt.UnixMilli()
	_, err := fmt.Fprintf(w, "%s %s %d %s %d\n",
		smtpPrefaceMagic,
		m.SenderIP.String(),
		m.SenderPort,
		m.DestIP.String(),
		ms,
	)
	return err
}

func ReadSMTPDeliveryPreface(r io.Reader) (SMTPDeliveryMeta, error) {
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil {
		return SMTPDeliveryMeta{}, err
	}
	line = strings.TrimRight(line, "\r\n")
	parts := strings.Split(line, " ")
	// Expected: SISUMAIL1 SMTP <ip> <port> <dest_ip> <ms>
	if len(parts) != 6 || parts[0]+" "+parts[1] != smtpPrefaceMagic {
		return SMTPDeliveryMeta{}, fmt.Errorf("invalid preface: %q", line)
	}
	sip := net.ParseIP(parts[2])
	if sip == nil {
		return SMTPDeliveryMeta{}, fmt.Errorf("invalid sender ip")
	}
	p, err := strconv.Atoi(parts[3])
	if err != nil || p < 1 || p > 65535 {
		return SMTPDeliveryMeta{}, fmt.Errorf("invalid sender port")
	}
	dip := net.ParseIP(parts[4])
	if dip == nil {
		return SMTPDeliveryMeta{}, fmt.Errorf("invalid dest ip")
	}
	ms, err := strconv.ParseInt(parts[5], 10, 64)
	if err != nil {
		return SMTPDeliveryMeta{}, fmt.Errorf("invalid timestamp")
	}
	return SMTPDeliveryMeta{
		SenderIP:   sip,
		SenderPort: p,
		DestIP:     dip,
		ReceivedAt: time.UnixMilli(ms),
	}, nil
}

// PrefaceReader returns an io.Reader that first yields meta preface bytes, then the remaining stream.
// Only used in tests; real code should call ReadSMTPDeliveryPreface and then continue reading from r.
func PrefaceReader(r io.Reader, meta SMTPDeliveryMeta) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		_ = WriteSMTPDeliveryPreface(pw, meta)
		_, _ = io.Copy(pw, r)
		_ = pw.Close()
	}()
	return pr
}
