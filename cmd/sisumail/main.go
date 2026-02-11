package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/mail"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/sisumail/sisumail/internal/core"
	"github.com/sisumail/sisumail/internal/store/maildir"
	"github.com/sisumail/sisumail/internal/proto"
	"github.com/sisumail/sisumail/internal/tier2"
	"github.com/sisumail/sisumail/internal/tlsboot"
	"golang.org/x/crypto/ssh"
)

func main() {
	var (
		relayAddr  = flag.String("relay", "127.0.0.1:2222", "relay SSH address (dev default 127.0.0.1:2222)")
		user       = flag.String("user", "niklas", "sisumail username")
		keyPath    = flag.String("key", filepath.Join(os.Getenv("HOME"), ".ssh", "id_ed25519"), "ssh private key path")
		smtpListen = flag.String("smtp-listen", "127.0.0.1:2526", "local SMTP daemon listen address")
		tlsPolicy  = flag.String("tls-policy", "pragmatic", "tls bootstrap policy: pragmatic|strict")
		certPath   = flag.String("tls-cert", "", "path to TLS cert PEM (optional; ACME will populate later)")
		keyPemPath = flag.String("tls-key", "", "path to TLS key PEM (optional; ACME will populate later)")
		maildirRoot = flag.String("maildir", filepath.Join(os.Getenv("HOME"), ".local", "share", "sisumail", "maildir"), "local Maildir root")
		inboxMode  = flag.Bool("inbox", false, "list local inbox and exit")
		readID     = flag.String("read-id", "", "read local message by ID and exit")
		tuiMode    = flag.Bool("tui", false, "interactive local inbox view")
	)
	flag.Parse()

	store := &maildir.Store{Root: *maildirRoot}
	if err := store.Init(); err != nil {
		log.Fatalf("maildir init: %v", err)
	}

	if *inboxMode {
		if err := printInbox(store); err != nil {
			log.Fatalf("inbox: %v", err)
		}
		return
	}
	if *readID != "" {
		if err := printMessage(store, *readID); err != nil {
			log.Fatalf("read-id: %v", err)
		}
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	host := fmt.Sprintf("v6.%s.sisumail.fi", *user)
	var primary tlsboot.Provider
	if *certPath != "" && *keyPemPath != "" {
		primary = &tlsboot.DiskProvider{CertPath: *certPath, KeyPath: *keyPemPath}
	}
	pol := tlsboot.ParsePolicy(*tlsPolicy)
	var provider tlsboot.Provider
	switch pol {
	case tlsboot.PolicyStrict:
		provider = &tlsboot.StrictProvider{Primary: primary}
	default:
		provider = &tlsboot.PragmaticProvider{
			Hostnames:         []string{host, "localhost"},
			Primary:           primary,
			SelfSignedValidity: 24 * time.Hour,
		}
	}

	res, err := provider.GetCertificate(time.Now())
	if err != nil {
		log.Fatalf("tls bootstrap (%s): %v", pol, err)
	}
	if !res.Encrypted {
		log.Fatalf("tls bootstrap (%s): no certificate available", pol)
	}

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{res.Cert}}
	log.Printf("tls: source=%s authenticated_ca=%v", res.Source, res.AuthenticatedCA)

	// Start local SMTP daemon.
	bridge := newDeliveryMetaBridge()
	backend := &localBackend{store: store, bridge: bridge}
	srv := smtp.NewServer(backend)
	srv.Addr = *smtpListen
	srv.Domain = host
	srv.AllowInsecureAuth = false
	srv.EnableSMTPUTF8 = false
	srv.TLSConfig = tlsCfg
	srv.ReadTimeout = 30 * time.Second
	srv.WriteTimeout = 30 * time.Second
	srv.MaxMessageBytes = 5 << 20
	srv.MaxRecipients = 10

	go func() {
		log.Printf("local smtp daemon listening on %s (STARTTLS required)", *smtpListen)
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("smtp daemon error: %v", err)
			cancel()
		}
	}()

	sshKey, err := os.ReadFile(*keyPath)
	if err != nil {
		log.Fatalf("read key: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(sshKey)
	if err != nil {
		log.Fatalf("parse key: %v", err)
	}

	sshCfg := &ssh.ClientConfig{
		User: *user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		// Dev: accept anything; production will pin host keys.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", *relayAddr, sshCfg)
	if err != nil {
		log.Fatalf("ssh dial: %v", err)
	}
	defer client.Close()
	log.Printf("connected to relay %s as %s", *relayAddr, *user)

	// Accept channels from relay (smtp-delivery).
	go func() {
		chans := client.HandleChannelOpen("smtp-delivery")
		for ch := range chans {
			go handleChannel(ch, *smtpListen, bridge)
		}
	}()

	// Accept Tier 2 spool deliveries from relay.
	go func() {
		chans := client.HandleChannelOpen("spool-delivery")
		for ch := range chans {
			go handleSpoolChannel(ch, string(sshKey), store)
		}
	}()

	if *tuiMode {
		if err := runInboxTUI(store); err != nil {
			log.Printf("tui error: %v", err)
		}
		cancel()
	}

	<-ctx.Done()
	_ = srv.Close()
}

func handleChannel(ch ssh.NewChannel, smtpListen string, bridge *deliveryMetaBridge) {
	if ch.ChannelType() != "smtp-delivery" {
		_ = ch.Reject(ssh.UnknownChannelType, "unsupported channel")
		return
	}
	channel, reqs, err := ch.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	defer channel.Close()

	// Read out-of-band preface.
	meta, err := proto.ReadSMTPDeliveryPreface(channel)
	if err != nil {
		return
	}
	log.Printf("smtp-delivery: from=%s:%d dest=%s at=%s",
		meta.SenderIP.String(), meta.SenderPort, meta.DestIP.String(), meta.ReceivedAt.Format(time.RFC3339))

	// Proxy raw bytes to local SMTP daemon.
	local, err := net.Dial("tcp", smtpListen)
	if err != nil {
		return
	}
	defer local.Close()
	if bridge != nil {
		bridge.Put(local.LocalAddr().String(), meta)
	}

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(local, channel); done <- struct{}{} }()
	go func() { _, _ = io.Copy(channel, local); done <- struct{}{} }()
	<-done
}

func handleSpoolChannel(ch ssh.NewChannel, sshPrivKey string, store *maildir.Store) {
	if ch.ChannelType() != "spool-delivery" {
		_ = ch.Reject(ssh.UnknownChannelType, "unsupported channel")
		return
	}
	channel, reqs, err := ch.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	defer channel.Close()

	h, br, err := proto.ReadSpoolDeliveryHeader(channel)
	if err != nil {
		return
	}

	// Decrypt ciphertext stream (bounded), persist locally, and ACK.
	lr := io.LimitReader(br, h.SizeBytes)
	var plain bytes.Buffer
	if err := tier2.StreamDecrypt(&plain, lr, sshPrivKey); err != nil {
		log.Printf("spool-delivery: decrypt failed msg=%s err=%v", h.MessageID, err)
		return
	}

	msg := injectSisumailHeaders(plain.Bytes(), map[string]string{
		"X-Sisumail-Tier":             "tier2",
		"X-Sisumail-Spool-Message-ID": h.MessageID,
		"X-Sisumail-Spool-Size":       fmt.Sprintf("%d", h.SizeBytes),
	})

	id, err := store.Deliver(bytes.NewReader(msg), "tier2")
	if err != nil {
		log.Printf("spool-delivery: local store failed msg=%s err=%v", h.MessageID, err)
		return
	}
	log.Printf("spool-delivery: stored msg=%s local_id=%s", h.MessageID, id)

	_ = proto.WriteSpoolAck(channel, h.MessageID)
}

type localBackend struct {
	store  *maildir.Store
	bridge *deliveryMetaBridge
}

func (b *localBackend) NewSession(conn *smtp.Conn) (smtp.Session, error) {
	_, isTLS := conn.TLSConnectionState()
	var meta *proto.SMTPDeliveryMeta
	if b != nil && b.bridge != nil && conn != nil && conn.Conn() != nil {
		if m, ok := b.bridge.Take(conn.Conn().RemoteAddr().String()); ok {
			meta = &m
		}
	}
	return &localSession{isTLS: isTLS, store: b.store, senderMeta: meta}, nil
}

type localSession struct {
	isTLS      bool
	store      *maildir.Store
	senderMeta *proto.SMTPDeliveryMeta
}

func (s *localSession) AuthPlain(username, password string) error { return smtp.ErrAuthUnsupported }
func (s *localSession) Mail(from string, opts *smtp.MailOptions) error {
	if !s.isTLS {
		return &smtp.SMTPError{
			Code:         530,
			EnhancedCode: smtp.EnhancedCode{5, 7, 0},
			Message:      "Must issue STARTTLS first",
		}
	}
	return nil
}
func (s *localSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	if !s.isTLS {
		return &smtp.SMTPError{
			Code:         530,
			EnhancedCode: smtp.EnhancedCode{5, 7, 0},
			Message:      "Must issue STARTTLS first",
		}
	}
	return nil
}
func (s *localSession) Data(r io.Reader) error {
	if !s.isTLS {
		return &smtp.SMTPError{
			Code:         530,
			EnhancedCode: smtp.EnhancedCode{5, 7, 0},
			Message:      "Must issue STARTTLS first",
		}
	}

	body, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	headers := map[string]string{
		"X-Sisumail-Tier": "tier1",
	}
	if s.senderMeta != nil {
		headers["X-Sisumail-Sender-IP"] = s.senderMeta.SenderIP.String()
		headers["X-Sisumail-Sender-Port"] = fmt.Sprintf("%d", s.senderMeta.SenderPort)
		headers["X-Sisumail-Dest-IP"] = s.senderMeta.DestIP.String()
		headers["X-Sisumail-Received-At"] = s.senderMeta.ReceivedAt.Format(time.RFC3339)
	}
	msg := injectSisumailHeaders(body, headers)

	if s.store == nil {
		return nil
	}
	if _, err := s.store.Deliver(bytes.NewReader(msg), "tier1"); err != nil {
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "local storage failed",
		}
	}
	return nil
}
func (s *localSession) Reset() {}
func (s *localSession) Logout() error { return nil }

type deliveryMetaBridge struct {
	mu   sync.Mutex
	byID map[string]proto.SMTPDeliveryMeta
}

func newDeliveryMetaBridge() *deliveryMetaBridge {
	return &deliveryMetaBridge{byID: make(map[string]proto.SMTPDeliveryMeta)}
}

func (b *deliveryMetaBridge) Put(connID string, meta proto.SMTPDeliveryMeta) {
	if b == nil || connID == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.byID[connID] = meta
}

func (b *deliveryMetaBridge) Take(connID string) (proto.SMTPDeliveryMeta, bool) {
	if b == nil || connID == "" {
		return proto.SMTPDeliveryMeta{}, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	meta, ok := b.byID[connID]
	if ok {
		delete(b.byID, connID)
	}
	return meta, ok
}

func injectSisumailHeaders(msg []byte, headers map[string]string) []byte {
	if len(headers) == 0 {
		return msg
	}

	var lines []string
	for k, v := range headers {
		if strings.TrimSpace(v) == "" {
			continue
		}
		lines = append(lines, k+": "+v)
	}
	if len(lines) == 0 {
		return msg
	}
	block := strings.Join(lines, "\r\n")

	sep := []byte("\r\n\r\n")
	i := bytes.Index(msg, sep)
	if i < 0 {
		return append([]byte(block+"\r\n\r\n"), msg...)
	}

	out := make([]byte, 0, len(msg)+len(block)+2)
	out = append(out, msg[:i]...)
	out = append(out, []byte("\r\n"+block)...)
	out = append(out, msg[i:]...)
	return out
}

func printInbox(store *maildir.Store) error {
	entries, err := store.List()
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Println("inbox empty")
		return nil
	}
	fmt.Printf("%-30s %-6s %-6s %-20s %s\n", "ID", "TIER", "STATE", "FROM", "SUBJECT")
	for _, e := range entries {
		from, subj := readSummary(store, e.ID)
		state := "unread"
		if e.Seen {
			state = "read"
		}
		fmt.Printf("%-30s %-6s %-6s %-20s %s\n", e.ID, strings.ToUpper(e.Tier), state, from, subj)
	}
	return nil
}

func printMessage(store *maildir.Store, id string) error {
	rc, err := store.Read(id)
	if err != nil {
		return err
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return err
	}
	_, _ = os.Stdout.Write(data)
	return nil
}

func readSummary(store *maildir.Store, id string) (from string, subject string) {
	from = "-"
	subject = "-"
	rc, err := store.Read(id)
	if err != nil {
		return from, subject
	}
	defer rc.Close()
	m, err := mail.ReadMessage(rc)
	if err != nil {
		return from, subject
	}
	if v := m.Header.Get("From"); v != "" {
		from = v
	}
	if v := m.Header.Get("Subject"); v != "" {
		subject = v
	}
	return from, subject
}

func runInboxTUI(store *maildir.Store) error {
	in := bufio.NewReader(os.Stdin)
	filter := inboxFilterAll

	for {
		entries, err := store.List()
		if err != nil {
			return err
		}
		view := applyInboxFilter(entries, filter)

		fmt.Println()
		fmt.Println("Sisumail Inbox (live)")
		fmt.Println("==============")
		fmt.Printf("Filter: %s\n", filter)
		if len(view) == 0 {
			fmt.Println("(empty)")
		} else {
			fmt.Printf("%-4s %-30s %-14s %-7s %-20s %s\n", "NO", "ID", "TIER", "STATE", "FROM", "SUBJECT")
			for i, e := range view {
				from, subj := readSummary(store, e.ID)
				state := "unread"
				if e.Seen {
					state = "read"
				}
				fmt.Printf("%-4d %-30s %-14s %-7s %-20s %s\n", i+1, e.ID, tierBadge(e.Tier), state, from, subj)
			}
		}
		fmt.Println()
		fmt.Print("Command [number=open, m <n>=mark-read, d <n>=delete, x <n>=archive, a|1|2|u filter, r refresh, q quit]: ")

		line, err := in.ReadString('\n')
		if err != nil {
			return err
		}
		cmd := strings.TrimSpace(line)
		switch cmd {
		case "", "r":
			continue
		case "q":
			return nil
		case "a":
			filter = inboxFilterAll
			continue
		case "1":
			filter = inboxFilterTier1
			continue
		case "2":
			filter = inboxFilterTier2
			continue
		case "u":
			filter = inboxFilterUnread
			continue
		}

		if strings.HasPrefix(cmd, "m ") {
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(cmd, "m ")))
			if err != nil || n < 1 || n > len(view) {
				fmt.Println("invalid selection")
				continue
			}
			if err := store.MarkRead(view[n-1].ID); err != nil {
				fmt.Printf("mark-read failed: %v\n", err)
			}
			continue
		}
		if strings.HasPrefix(cmd, "d ") {
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(cmd, "d ")))
			if err != nil || n < 1 || n > len(view) {
				fmt.Println("invalid selection")
				continue
			}
			if err := store.Delete(view[n-1].ID); err != nil {
				fmt.Printf("delete failed: %v\n", err)
			}
			continue
		}
		if strings.HasPrefix(cmd, "x ") {
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(cmd, "x ")))
			if err != nil || n < 1 || n > len(view) {
				fmt.Println("invalid selection")
				continue
			}
			if err := store.Archive(view[n-1].ID); err != nil {
				fmt.Printf("archive failed: %v\n", err)
			}
			continue
		}

		n, err := strconv.Atoi(cmd)
		if err != nil || n < 1 || n > len(view) {
			fmt.Println("invalid selection")
			continue
		}
		if err := store.MarkRead(view[n-1].ID); err != nil {
			fmt.Printf("mark-read failed: %v\n", err)
		}
		if err := printMessageView(store, view[n-1].ID, in); err != nil {
			fmt.Printf("open failed: %v\n", err)
		}
	}
}

type inboxFilter string

const (
	inboxFilterAll    inboxFilter = "all"
	inboxFilterTier1  inboxFilter = "tier1"
	inboxFilterTier2  inboxFilter = "tier2"
	inboxFilterUnread inboxFilter = "unread"
)

func applyInboxFilter(entries []core.MaildirEntry, filter inboxFilter) []core.MaildirEntry {
	if filter == inboxFilterAll {
		return entries
	}
	out := make([]core.MaildirEntry, 0, len(entries))
	for _, e := range entries {
		switch filter {
		case inboxFilterTier1:
			if strings.EqualFold(e.Tier, "tier1") {
				out = append(out, e)
			}
		case inboxFilterTier2:
			if strings.EqualFold(e.Tier, "tier2") {
				out = append(out, e)
			}
		case inboxFilterUnread:
			if !e.Seen {
				out = append(out, e)
			}
		default:
			out = append(out, e)
		}
	}
	return out
}

func printMessageView(store *maildir.Store, id string, in *bufio.Reader) error {
	rc, err := store.Read(id)
	if err != nil {
		return err
	}
	defer rc.Close()

	m, err := mail.ReadMessage(rc)
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("Message %s\n", id)
	fmt.Println(strings.Repeat("-", 72))
	fmt.Printf("Tier: %s\n", tierBadge(m.Header.Get("X-Sisumail-Tier")))
	fmt.Printf("From: %s\n", nonEmpty(m.Header.Get("From")))
	fmt.Printf("To: %s\n", nonEmpty(m.Header.Get("To")))
	fmt.Printf("Subject: %s\n", nonEmpty(m.Header.Get("Subject")))
	fmt.Printf("Date: %s\n", nonEmpty(m.Header.Get("Date")))

	if v := m.Header.Get("X-Sisumail-Sender-IP"); v != "" {
		fmt.Printf("Sender IP: %s\n", v)
	}
	if v := m.Header.Get("X-Sisumail-Sender-Port"); v != "" {
		fmt.Printf("Sender Port: %s\n", v)
	}
	if v := m.Header.Get("X-Sisumail-Dest-IP"); v != "" {
		fmt.Printf("Dest IP: %s\n", v)
	}
	if v := m.Header.Get("X-Sisumail-Received-At"); v != "" {
		fmt.Printf("Received At: %s\n", v)
	}
	if v := m.Header.Get("X-Sisumail-Spool-Message-ID"); v != "" {
		fmt.Printf("Spool Message ID: %s\n", v)
	}
	if v := m.Header.Get("X-Sisumail-Spool-Size"); v != "" {
		fmt.Printf("Spool Size: %s\n", v)
	}

	body, _ := io.ReadAll(m.Body)
	fmt.Println(strings.Repeat("-", 72))
	fmt.Print(string(body))
	if len(body) == 0 || body[len(body)-1] != '\n' {
		fmt.Println()
	}
	fmt.Println(strings.Repeat("-", 72))
	fmt.Print("Press Enter to return to inbox...")
	_, _ = in.ReadString('\n')
	return nil
}

func tierBadge(tier string) string {
	switch strings.ToLower(strings.TrimSpace(tier)) {
	case "tier1":
		return "Tier1 Blind"
	case "tier2":
		return "Tier2 Spool"
	default:
		if strings.TrimSpace(tier) == "" {
			return "Unknown"
		}
		return tier
	}
}

func nonEmpty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
