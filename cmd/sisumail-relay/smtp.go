package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"github.com/sisumail/sisumail/internal/identity"
)

type smtpIngress struct {
	listenAddr        string
	zone              string
	store             *identity.Store
	ttl               time.Duration
	maxConcurrent     int
	perIPPerMinute    int
	maxDataBytes      int
	maxRcptPerSession int
	metrics           *appMetrics

	mu      sync.Mutex
	ipHits  map[string][]time.Time
	connSem chan struct{}
}

func (s *smtpIngress) run(ctx context.Context) error {
	if strings.TrimSpace(s.listenAddr) == "" {
		return nil
	}
	if s.maxConcurrent <= 0 {
		s.maxConcurrent = 200
	}
	if s.maxDataBytes <= 0 {
		s.maxDataBytes = 256 * 1024
	}
	if s.maxRcptPerSession <= 0 {
		s.maxRcptPerSession = 10
	}
	if s.connSem == nil {
		s.connSem = make(chan struct{}, s.maxConcurrent)
	}
	if s.ipHits == nil {
		s.ipHits = make(map[string][]time.Time)
	}
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	log.Printf("smtp ingress listening on %s", s.listenAddr)
	defer ln.Close()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			return err
		}
		select {
		case s.connSem <- struct{}{}:
			go s.handleConn(c)
		default:
			_, _ = c.Write([]byte("421 too many connections\r\n"))
			_ = c.Close()
			if s.metrics != nil {
				s.metrics.smtpRejectedTotal.Add(1)
			}
		}
	}
}

func (s *smtpIngress) handleConn(c net.Conn) {
	defer func() { <-s.connSem }()
	defer c.Close()
	if s.metrics != nil {
		s.metrics.smtpConnectionsCurrent.Add(1)
		s.metrics.smtpConnectionsTotal.Add(1)
		defer s.metrics.smtpConnectionsCurrent.Add(-1)
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
	r := textproto.NewReader(bufio.NewReader(c))
	w := bufio.NewWriter(c)
	writeSMTPLine(w, "220 sisumail relay ready")

	var (
		mailFrom string
		rcptTo   string
		rcptN    int
	)
	for {
		line, err := r.ReadLine()
		if err != nil {
			if err != io.EOF {
				writeSMTPLine(w, "421 read error")
			}
			return
		}
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		if host == "" {
			host = c.RemoteAddr().String()
		}
		if !s.allowIP(host, time.Now()) {
			writeSMTPLine(w, "421 rate limited")
			if s.metrics != nil {
				s.metrics.smtpRejectedTotal.Add(1)
			}
			return
		}
		cmd, arg := splitSMTP(strings.TrimSpace(line))
		switch strings.ToUpper(cmd) {
		case "EHLO", "HELO":
			writeSMTPLine(w, "250 relay")
		case "MAIL":
			if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(arg)), "FROM:") {
				writeSMTPLine(w, "501 syntax")
				continue
			}
			mailFrom = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(arg), "FROM:"))
			writeSMTPLine(w, "250 ok")
		case "RCPT":
			if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(arg)), "TO:") {
				writeSMTPLine(w, "501 syntax")
				continue
			}
			rcptTo = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(arg), "TO:"))
			rcptN++
			if rcptN > s.maxRcptPerSession {
				writeSMTPLine(w, "452 too many recipients")
				if s.metrics != nil {
					s.metrics.smtpRejectedTotal.Add(1)
				}
				continue
			}
			writeSMTPLine(w, "250 ok")
		case "DATA":
			if mailFrom == "" || rcptTo == "" {
				writeSMTPLine(w, "503 need MAIL FROM and RCPT TO first")
				continue
			}
			writeSMTPLine(w, "354 end with <CRLF>.<CRLF>")
			msg, err := readSMTPData(r, s.maxDataBytes)
			if err != nil {
				if errors.Is(err, errSMTPDataTooLarge) {
					writeSMTPLine(w, "552 data too large")
					if s.metrics != nil {
						s.metrics.smtpRejectedTotal.Add(1)
					}
					continue
				}
				writeSMTPLine(w, "451 data read error")
				continue
			}
			username, alias, err := parseRecipient(rcptTo, s.zone)
			if err != nil {
				writeSMTPLine(w, "550 invalid recipient")
				continue
			}
			ciphertext := strings.TrimSpace(msg)
			if !isCiphertextPayload(ciphertext) {
				writeSMTPLine(w, "550 plaintext rejected (ciphertext required)")
				if s.metrics != nil {
					s.metrics.smtpRejectedTotal.Add(1)
				}
				continue
			}
			enqueueCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err = s.store.EnqueueCiphertext(enqueueCtx, username, alias, mailFrom, ciphertext, s.ttl)
			cancel()
			if err != nil {
				writeSMTPLine(w, "550 reject: "+sanitizeSMTPErr(err))
				if s.metrics != nil {
					s.metrics.smtpRejectedTotal.Add(1)
				}
				continue
			}
			writeSMTPLine(w, "250 queued")
			if s.metrics != nil {
				s.metrics.smtpAcceptedTotal.Add(1)
			}
		case "RSET":
			mailFrom = ""
			rcptTo = ""
			rcptN = 0
			writeSMTPLine(w, "250 reset")
		case "NOOP":
			writeSMTPLine(w, "250 ok")
		case "QUIT":
			writeSMTPLine(w, "221 bye")
			return
		default:
			writeSMTPLine(w, "502 not implemented")
		}
	}
}

func (s *smtpIngress) allowIP(ip string, now time.Time) bool {
	if s.perIPPerMinute <= 0 {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	window := now.Add(-1 * time.Minute)
	hits := s.ipHits[ip]
	kept := hits[:0]
	for _, t := range hits {
		if t.After(window) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= s.perIPPerMinute {
		s.ipHits[ip] = kept
		return false
	}
	kept = append(kept, now)
	s.ipHits[ip] = kept
	return true
}

func splitSMTP(line string) (cmd, arg string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}
	parts := strings.SplitN(line, " ", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}

func writeSMTPLine(w *bufio.Writer, s string) {
	_, _ = w.WriteString(s + "\r\n")
	_ = w.Flush()
}

var errSMTPDataTooLarge = errors.New("smtp data too large")

func readSMTPData(r *textproto.Reader, maxBytes int) (string, error) {
	var b strings.Builder
	for {
		line, err := r.ReadLine()
		if err != nil {
			return "", err
		}
		if line == "." {
			break
		}
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		b.WriteString(line)
		b.WriteString("\n")
		if maxBytes > 0 && b.Len() > maxBytes {
			return "", errSMTPDataTooLarge
		}
	}
	return b.String(), nil
}

func parseRecipient(raw, zone string) (username, alias string, err error) {
	addr := strings.Trim(strings.TrimSpace(raw), "<>")
	parts := strings.Split(addr, "@")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid recipient")
	}
	local := strings.ToLower(strings.TrimSpace(parts[0]))
	host := strings.ToLower(strings.TrimSpace(parts[1]))
	zone = strings.ToLower(strings.TrimSpace(zone))
	if local == "" || host == "" || zone == "" {
		return "", "", fmt.Errorf("invalid recipient")
	}
	// root address form: username@zone
	if host == zone {
		u, err := identity.CanonicalUsername(local)
		if err != nil {
			return "", "", err
		}
		return u, fmt.Sprintf("%s@%s", u, zone), nil
	}
	// alias form: service@username.zone
	suffix := "." + zone
	if !strings.HasSuffix(host, suffix) {
		return "", "", fmt.Errorf("invalid host")
	}
	userPart := strings.TrimSuffix(host, suffix)
	u, err := identity.CanonicalUsername(userPart)
	if err != nil {
		return "", "", err
	}
	alias = fmt.Sprintf("%s@%s", local, host)
	return u, alias, nil
}

func isCiphertextPayload(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	// enforce "near-E2E relay only" posture by rejecting obvious plaintext.
	// accepted prefixes are intentionally strict for now.
	if strings.HasPrefix(s, "ciphertext:") || strings.HasPrefix(s, "age1") || strings.HasPrefix(s, "ENC:") {
		return true
	}
	return false
}

func sanitizeSMTPErr(err error) string {
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case strings.Contains(msg, "not active"):
		return "account not active"
	case strings.Contains(msg, "not found"):
		return "unknown user"
	default:
		return "policy"
	}
}
