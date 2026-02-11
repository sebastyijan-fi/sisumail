package proto

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

type ACMEDNS01Request struct {
	Op       string // PRESENT or CLEANUP
	Hostname string
	Value    string
}

type ACMEDNS01Response struct {
	OK      bool
	Message string
}

func WriteACMEDNS01Request(w io.Writer, r ACMEDNS01Request) error {
	op := strings.ToUpper(strings.TrimSpace(r.Op))
	host := strings.TrimSpace(r.Hostname)
	val := strings.TrimSpace(r.Value)
	if op == "" || host == "" || val == "" {
		return fmt.Errorf("invalid acme request")
	}
	_, err := fmt.Fprintf(w, "ACME1 %s %s %s\n", op, host, val)
	return err
}

func ReadACMEDNS01Request(r io.Reader) (ACMEDNS01Request, error) {
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil {
		return ACMEDNS01Request{}, err
	}
	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 5)
	if len(parts) != 4 || parts[0] != "ACME1" {
		return ACMEDNS01Request{}, fmt.Errorf("invalid acme request")
	}
	req := ACMEDNS01Request{
		Op:       strings.ToUpper(strings.TrimSpace(parts[1])),
		Hostname: strings.TrimSpace(parts[2]),
		Value:    strings.TrimSpace(parts[3]),
	}
	if req.Op == "" || req.Hostname == "" || req.Value == "" {
		return ACMEDNS01Request{}, fmt.Errorf("invalid acme request")
	}
	return req, nil
}

func WriteACMEDNS01Response(w io.Writer, resp ACMEDNS01Response) error {
	if resp.OK {
		_, err := fmt.Fprint(w, "ACME1 OK\n")
		return err
	}
	msg := strings.TrimSpace(resp.Message)
	if msg == "" {
		msg = "error"
	}
	msg = strings.ReplaceAll(msg, "\n", " ")
	_, err := fmt.Fprintf(w, "ACME1 ERR %s\n", msg)
	return err
}

func ReadACMEDNS01Response(r io.Reader) (ACMEDNS01Response, error) {
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil {
		return ACMEDNS01Response{}, err
	}
	line = strings.TrimSpace(line)
	if line == "ACME1 OK" {
		return ACMEDNS01Response{OK: true}, nil
	}
	if strings.HasPrefix(line, "ACME1 ERR ") {
		return ACMEDNS01Response{OK: false, Message: strings.TrimSpace(strings.TrimPrefix(line, "ACME1 ERR "))}, nil
	}
	return ACMEDNS01Response{}, fmt.Errorf("invalid acme response")
}
