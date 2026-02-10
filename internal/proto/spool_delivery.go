package proto

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// SpoolDeliveryHeader is the out-of-band header for a Tier 2 spool delivery.
//
// Wire format (single line, ASCII):
//   SPOOL <msg_id> <size_bytes>\n
//
// Followed by exactly <size_bytes> of age ciphertext (not framed further).
type SpoolDeliveryHeader struct {
	MessageID string
	SizeBytes int64
}

func WriteSpoolDeliveryHeader(w io.Writer, h SpoolDeliveryHeader) error {
	if h.MessageID == "" {
		return fmt.Errorf("missing message id")
	}
	if h.SizeBytes <= 0 {
		return fmt.Errorf("invalid size")
	}
	_, err := fmt.Fprintf(w, "SPOOL %s %d\n", h.MessageID, h.SizeBytes)
	return err
}

// ReadSpoolDeliveryHeader reads a single header line from r.
// It does not read the ciphertext payload.
func ReadSpoolDeliveryHeader(r io.Reader) (SpoolDeliveryHeader, *bufio.Reader, error) {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	line, err := br.ReadString('\n')
	if err != nil {
		return SpoolDeliveryHeader{}, br, err
	}
	line = strings.TrimSpace(line)
	parts := strings.Split(line, " ")
	if len(parts) != 3 || parts[0] != "SPOOL" {
		return SpoolDeliveryHeader{}, br, fmt.Errorf("invalid spool header")
	}
	n, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || n <= 0 {
		return SpoolDeliveryHeader{}, br, fmt.Errorf("invalid spool size")
	}
	return SpoolDeliveryHeader{MessageID: parts[1], SizeBytes: n}, br, nil
}

func WriteSpoolAck(w io.Writer, msgID string) error {
	if msgID == "" {
		return fmt.Errorf("missing message id")
	}
	_, err := fmt.Fprintf(w, "ACK %s\n", msgID)
	return err
}

func ReadSpoolAck(r io.Reader, wantMsgID string) error {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	line = strings.TrimSpace(line)
	parts := strings.Split(line, " ")
	if len(parts) != 2 || parts[0] != "ACK" || parts[1] != wantMsgID {
		return fmt.Errorf("invalid ack")
	}
	return nil
}

