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
	"github.com/sisumail/sisumail/internal/store/chatlog"
	"github.com/sisumail/sisumail/internal/store/knownkeys"
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
		chatTo     = flag.String("chat-to", "", "send encrypted chat message to username (relay session must be online)")
		chatMsg    = flag.String("chat-msg", "", "chat message text (required with -chat-to)")
		chatWith   = flag.String("chat-with", "", "interactive chat session with username")
		chatDir    = flag.String("chat-dir", filepath.Join(os.Getenv("HOME"), ".local", "share", "sisumail", "chat"), "local chat history directory")
		knownKeysPath = flag.String("known-keys", filepath.Join(os.Getenv("HOME"), ".local", "share", "sisumail", "known_keys.json"), "pinned peer key fingerprints")
		chatHistory = flag.String("chat-history", "", "print chat history with username and exit")
		chatLimit  = flag.Int("chat-limit", 100, "max chat history lines for -chat-history (0 = unlimited)")
	)
	flag.Parse()
	if *tuiMode && strings.TrimSpace(*chatWith) != "" {
		log.Fatalf("-tui and -chat-with both use stdin; choose one")
	}

	store := &maildir.Store{Root: *maildirRoot}
	if err := store.Init(); err != nil {
		log.Fatalf("maildir init: %v", err)
	}
	chats := &chatlog.Store{Root: *chatDir}
	if err := chats.Init(); err != nil {
		log.Fatalf("chatlog init: %v", err)
	}
	known := &knownkeys.Store{Path: *knownKeysPath}

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
	if strings.TrimSpace(*chatHistory) != "" {
		if err := printChatHistory(chats, *chatHistory, *chatLimit); err != nil {
			log.Fatalf("chat-history: %v", err)
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
	go func() {
		chans := client.HandleChannelOpen("chat-delivery")
		for ch := range chans {
			go handleChatDeliveryChannel(ch, string(sshKey), chats)
		}
	}()

	if strings.TrimSpace(*chatTo) != "" {
		if strings.TrimSpace(*chatMsg) == "" {
			log.Fatalf("-chat-msg is required with -chat-to")
		}
		if err := sendChat(client, known, *chatTo, *chatMsg); err != nil {
			log.Printf("chat send failed: %v", err)
		} else {
			_ = chats.Append(*chatTo, "out", strings.TrimSpace(*chatMsg), time.Now())
			log.Printf("chat sent: from=%s to=%s", *user, *chatTo)
		}
		if !*tuiMode {
			cancel()
		}
	}
	if strings.TrimSpace(*chatWith) != "" {
		if err := runChatREPL(client, chats, known, *chatWith); err != nil {
			log.Printf("chat session failed: %v", err)
		}
		if !*tuiMode {
			cancel()
		}
	}

	if *tuiMode {
		if err := runInboxTUI(store, client, chats, known); err != nil {
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

func handleChatDeliveryChannel(ch ssh.NewChannel, sshPrivKey string, chats *chatlog.Store) {
	if ch.ChannelType() != "chat-delivery" {
		_ = ch.Reject(ssh.UnknownChannelType, "unsupported channel")
		return
	}
	channel, reqs, err := ch.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	defer channel.Close()

	h, br, err := proto.ReadChatDeliveryHeader(channel)
	if err != nil {
		return
	}
	lr := io.LimitReader(br, h.SizeBytes)
	var plain bytes.Buffer
	if err := tier2.StreamDecrypt(&plain, lr, sshPrivKey); err != nil {
		log.Printf("chat-delivery: decrypt failed from=%s err=%v", h.From, err)
		return
	}
	msg := strings.TrimSpace(plain.String())
	log.Printf("chat-delivery: from=%s msg=%q", h.From, msg)
	if chats != nil {
		_ = chats.Append(h.From, "in", msg, time.Now())
	}
	_ = proto.WriteChatAck(channel, h.MessageID)
}

func sendChat(client *ssh.Client, known *knownkeys.Store, toUser, message string) error {
	pubKey, fp, err := lookupAndTrustUserPubKey(client, known, toUser)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", toUser, err)
	}
	var ct bytes.Buffer
	if err := tier2.StreamEncrypt(&ct, strings.NewReader(message), pubKey); err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	ch, reqs, err := client.OpenChannel("chat-send", nil)
	if err != nil {
		return err
	}
	go ssh.DiscardRequests(reqs)
	defer ch.Close()

	if err := proto.WriteChatSendHeader(ch, proto.ChatSendHeader{
		To:        toUser,
		SizeBytes: int64(ct.Len()),
	}); err != nil {
		return err
	}
	_, err = io.Copy(ch, &ct)
	if err == nil && strings.TrimSpace(fp) != "" {
		log.Printf("chat peer key: user=%s fp=%s", toUser, fp)
	}
	return err
}

func runChatREPL(client *ssh.Client, chats *chatlog.Store, known *knownkeys.Store, peer string) error {
	peer = strings.TrimSpace(peer)
	if peer == "" {
		return fmt.Errorf("empty peer")
	}

	fmt.Printf("Chat session with %s\n", peer)
	fmt.Println("Type messages and press Enter. Commands: /quit, /history")
	in := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("> ")
		line, err := in.ReadString('\n')
		if err != nil {
			return err
		}
		msg := strings.TrimSpace(line)
		switch msg {
		case "":
			continue
		case "/quit":
			return nil
		case "/history":
			_ = printChatHistory(chats, peer, 20)
			continue
		}

		if err := sendChat(client, known, peer, msg); err != nil {
			fmt.Printf("send failed: %v\n", err)
			continue
		}
		if chats != nil {
			_ = chats.Append(peer, "out", msg, time.Now())
		}
		fmt.Println("sent")
	}
}

func lookupUserPubKey(client *ssh.Client, username string) (string, error) {
	ch, reqs, err := client.OpenChannel("key-lookup", nil)
	if err != nil {
		return "", err
	}
	go ssh.DiscardRequests(reqs)
	defer ch.Close()

	if err := proto.WriteKeyLookupRequest(ch, username); err != nil {
		return "", err
	}
	return proto.ReadKeyLookupResponse(ch)
}

func lookupAndTrustUserPubKey(client *ssh.Client, known *knownkeys.Store, username string) (pubKey string, fingerprint string, err error) {
	pub, err := lookupUserPubKey(client, username)
	if err != nil {
		return "", "", err
	}
	fp, err := sshFingerprint(pub)
	if err != nil {
		return "", "", err
	}
	if known != nil {
		status, prev, err := known.CheckAndUpdate(username, fp)
		if err != nil {
			log.Printf("known-keys update failed user=%s err=%v", username, err)
		} else {
			switch status {
			case "new":
				log.Printf("chat peer key pinned: user=%s fp=%s", username, fp)
			case "changed":
				log.Printf("WARNING: chat peer key changed: user=%s old=%s new=%s", username, prev, fp)
			}
		}
	}
	return pub, fp, nil
}

func sshFingerprint(pubKeyText string) (string, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyText))
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(pub), nil
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
	fmt.Printf("%-30s %-6s %-6s %-13s %-20s %s\n", "ID", "TIER", "STATE", "TRUST", "FROM", "SUBJECT")
	for _, e := range entries {
		sum := readSummaryInfo(store, e.ID, e.Tier)
		state := "unread"
		if e.Seen {
			state = "read"
		}
		fmt.Printf("%-30s %-6s %-6s %-13s %-20s %s\n", e.ID, strings.ToUpper(e.Tier), state, sum.Trust, sum.From, sum.Subject)
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

func printChatHistory(chats *chatlog.Store, peer string, limit int) error {
	list, err := chats.List(peer, limit)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Printf("no chat history with %s\n", peer)
		return nil
	}
	for _, e := range list {
		dir := "IN "
		if e.Direction == "out" {
			dir = "OUT"
		}
		fmt.Printf("%s %-3s %s\n", e.At.Format(time.RFC3339), dir, e.Message)
	}
	return nil
}

type summaryInfo struct {
	From    string
	Subject string
	Trust   string
}

func readSummaryInfo(store *maildir.Store, id string, tier string) summaryInfo {
	sum := summaryInfo{From: "-", Subject: "-", Trust: trustSummary(tier, nil)}
	rc, err := store.Read(id)
	if err != nil {
		return sum
	}
	defer rc.Close()
	m, err := mail.ReadMessage(rc)
	if err != nil {
		return sum
	}
	if v := m.Header.Get("From"); v != "" {
		sum.From = v
	}
	if v := m.Header.Get("Subject"); v != "" {
		sum.Subject = v
	}
	sum.Trust = trustSummary(tier, m.Header)
	return sum
}

func runInboxTUI(store *maildir.Store, client *ssh.Client, chats *chatlog.Store, known *knownkeys.Store) error {
	in := bufio.NewReader(os.Stdin)
	filter := inboxFilterAll
	search := ""
	page := 1
	const pageSize = 20

	for {
		entries, err := store.List()
		if err != nil {
			return err
		}
		filtered := applyInboxFilter(entries, filter)
		rows := buildInboxRows(store, filtered)
		rows = applySearchRows(rows, search)
		pageRows, totalPages := paginateRows(rows, page, pageSize)
		if page > totalPages {
			page = totalPages
			pageRows, totalPages = paginateRows(rows, page, pageSize)
		}
		if page < 1 {
			page = 1
		}

		fmt.Println()
		fmt.Println("Sisumail Inbox (live)")
		fmt.Println("==============")
		fmt.Printf("Filter: %s\n", filter)
		if strings.TrimSpace(search) != "" {
			fmt.Printf("Search: %q\n", search)
		}
		fmt.Printf("Page: %d/%d (total %d)\n", page, totalPages, len(rows))
		if len(pageRows) == 0 {
			fmt.Println("(empty)")
		} else {
			fmt.Printf("%-4s %-30s %-14s %-7s %-13s %-20s %s\n", "NO", "ID", "TIER", "STATE", "TRUST", "FROM", "SUBJECT")
			for i, r := range pageRows {
				e := r.Entry
				state := "unread"
				if e.Seen {
					state = "read"
				}
				fmt.Printf("%-4d %-30s %-14s %-7s %-13s %-20s %s\n", i+1, e.ID, tierBadge(e.Tier), state, r.Trust, r.From, r.Subject)
			}
		}
		fmt.Println()
		fmt.Print("Command [number=open, m/d/x <n>, a|1|2|u filter, /term search, / clear, n/p page, h <user>, c <user> <msg>, r refresh, q quit]: ")

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
			page = 1
			continue
		case "1":
			filter = inboxFilterTier1
			page = 1
			continue
		case "2":
			filter = inboxFilterTier2
			page = 1
			continue
		case "u":
			filter = inboxFilterUnread
			page = 1
			continue
		case "n":
			if page < totalPages {
				page++
			}
			continue
		case "p":
			if page > 1 {
				page--
			}
			continue
		case "/":
			search = ""
			page = 1
			continue
		}
		if strings.HasPrefix(cmd, "/") {
			search = strings.TrimSpace(strings.TrimPrefix(cmd, "/"))
			page = 1
			continue
		}
		if strings.HasPrefix(cmd, "h ") {
			peer := strings.TrimSpace(strings.TrimPrefix(cmd, "h "))
			if peer == "" {
				fmt.Println("usage: h <user>")
				continue
			}
			if chats == nil {
				fmt.Println("chat history unavailable")
				continue
			}
			_ = printChatHistory(chats, peer, 30)
			fmt.Print("Press Enter to return to inbox...")
			_, _ = in.ReadString('\n')
			continue
		}
		if strings.HasPrefix(cmd, "c ") {
			peer, msg, ok := parseChatSendCommand(cmd)
			if !ok {
				fmt.Println("usage: c <user> <message>")
				continue
			}
			if client == nil {
				fmt.Println("chat send unavailable (no relay connection)")
				continue
			}
			if err := sendChat(client, known, peer, msg); err != nil {
				fmt.Printf("chat send failed: %v\n", err)
				continue
			}
			if chats != nil {
				_ = chats.Append(peer, "out", msg, time.Now())
			}
			fmt.Println("chat sent")
			continue
		}

		if strings.HasPrefix(cmd, "m ") {
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(cmd, "m ")))
			if err != nil || n < 1 || n > len(pageRows) {
				fmt.Println("invalid selection")
				continue
			}
			if err := store.MarkRead(pageRows[n-1].Entry.ID); err != nil {
				fmt.Printf("mark-read failed: %v\n", err)
			}
			continue
		}
		if strings.HasPrefix(cmd, "d ") {
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(cmd, "d ")))
			if err != nil || n < 1 || n > len(pageRows) {
				fmt.Println("invalid selection")
				continue
			}
			if err := store.Delete(pageRows[n-1].Entry.ID); err != nil {
				fmt.Printf("delete failed: %v\n", err)
			}
			continue
		}
		if strings.HasPrefix(cmd, "x ") {
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(cmd, "x ")))
			if err != nil || n < 1 || n > len(pageRows) {
				fmt.Println("invalid selection")
				continue
			}
			if err := store.Archive(pageRows[n-1].Entry.ID); err != nil {
				fmt.Printf("archive failed: %v\n", err)
			}
			continue
		}

		n, err := strconv.Atoi(cmd)
		if err != nil || n < 1 || n > len(pageRows) {
			fmt.Println("invalid selection")
			continue
		}
		targetID := pageRows[n-1].Entry.ID
		if err := store.MarkRead(targetID); err != nil {
			fmt.Printf("mark-read failed: %v\n", err)
		}
		if err := printMessageView(store, targetID, in); err != nil {
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

type inboxRow struct {
	Entry   core.MaildirEntry
	From    string
	Subject string
	Trust   string
}

func buildInboxRows(store *maildir.Store, entries []core.MaildirEntry) []inboxRow {
	out := make([]inboxRow, 0, len(entries))
	for _, e := range entries {
		sum := readSummaryInfo(store, e.ID, e.Tier)
		out = append(out, inboxRow{
			Entry:   e,
			From:    sum.From,
			Subject: sum.Subject,
			Trust:   sum.Trust,
		})
	}
	return out
}

func applySearchRows(rows []inboxRow, term string) []inboxRow {
	term = strings.ToLower(strings.TrimSpace(term))
	if term == "" {
		return rows
	}
	out := make([]inboxRow, 0, len(rows))
	for _, r := range rows {
		hay := strings.ToLower(r.Entry.ID + " " + r.From + " " + r.Subject + " " + r.Trust)
		if strings.Contains(hay, term) {
			out = append(out, r)
		}
	}
	return out
}

func paginateRows(rows []inboxRow, page, pageSize int) ([]inboxRow, int) {
	if pageSize <= 0 {
		pageSize = 20
	}
	totalPages := (len(rows) + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	if page < 1 {
		page = 1
	}
	if page > totalPages {
		page = totalPages
	}

	start := (page - 1) * pageSize
	if start >= len(rows) {
		return nil, totalPages
	}
	end := start + pageSize
	if end > len(rows) {
		end = len(rows)
	}
	return rows[start:end], totalPages
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

func trustSummary(tier string, h mail.Header) string {
	get := func(k string) string {
		if h == nil {
			return ""
		}
		return strings.TrimSpace(h.Get(k))
	}

	switch strings.ToLower(strings.TrimSpace(tier)) {
	case "tier1":
		hasIP := get("X-Sisumail-Sender-IP") != ""
		hasAt := get("X-Sisumail-Received-At") != ""
		if hasIP && hasAt {
			return "blind+meta"
		}
		if hasIP || hasAt {
			return "blind+partial"
		}
		return "blind+nometa"
	case "tier2":
		hasID := get("X-Sisumail-Spool-Message-ID") != ""
		hasSize := get("X-Sisumail-Spool-Size") != ""
		if hasID && hasSize {
			return "spool+proof"
		}
		if hasID || hasSize {
			return "spool+partial"
		}
		return "spool+noproof"
	default:
		return "unknown"
	}
}

func nonEmpty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func parseChatSendCommand(cmd string) (peer string, msg string, ok bool) {
	rest := strings.TrimSpace(strings.TrimPrefix(cmd, "c "))
	if rest == "" {
		return "", "", false
	}
	parts := strings.SplitN(rest, " ", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	peer = strings.TrimSpace(parts[0])
	msg = strings.TrimSpace(parts[1])
	if peer == "" || msg == "" {
		return "", "", false
	}
	return peer, msg, true
}
