package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sisumail/sisumail/internal/dns/hetznercloud"
	"github.com/sisumail/sisumail/internal/identity"
	"github.com/sisumail/sisumail/internal/observability"
	"github.com/sisumail/sisumail/internal/proto"
	"github.com/sisumail/sisumail/internal/provision"
	"github.com/sisumail/sisumail/internal/relay"
	"github.com/sisumail/sisumail/internal/store/chatqueue"
	"github.com/sisumail/sisumail/internal/tier2"
	"golang.org/x/crypto/ssh"
)

func main() {
	var (
		sshListen              = flag.String("ssh-listen", ":2222", "SSH gateway listen address (dev default :2222)")
		tier1Listen            = flag.String("tier1-listen", ":2525", "Tier 1 TCP proxy listen address (dev default :2525)")
		tier1FastFailMS        = flag.Int("tier1-fast-fail-ms", 200, "Tier 1 fast-fail timeout in milliseconds")
		tier1OpenTimeoutMS     = flag.Int("tier1-open-timeout-ms", 3000, "Tier 1 SSH channel-open timeout in milliseconds")
		tier1IdleTimeoutMS     = flag.Int("tier1-idle-timeout-ms", 120000, "Tier 1 idle I/O timeout in milliseconds")
		tier1MaxConnDurationMS = flag.Int("tier1-max-conn-duration-ms", 600000, "Tier 1 max connection duration in milliseconds")
		tier1MaxBytesPerConn   = flag.Int64("tier1-max-bytes-per-conn", 10<<20, "Tier 1 max proxied bytes per connection (both directions combined)")
		tier1MaxPerUser        = flag.Int("tier1-max-conns-per-user", 10, "Tier 1 max concurrent connections per user")
		tier1MaxPerSource      = flag.Int("tier1-max-conns-per-source", 20, "Tier 1 max concurrent connections per source IP")
		devUser                = flag.String("dev-user", "", "dev-only: route all Tier 1 traffic to this username (empty disables)")
		hostKeyPath            = flag.String("hostkey", "./data/relay_hostkey_ed25519", "path to relay SSH host key (created if missing)")
		dbPath                 = flag.String("db", "./data/relay.db", "identity registry sqlite path")
		initDB                 = flag.Bool("init-db", false, "initialize database schema and exit")
		addUser                = flag.Bool("add-user", false, "add/update an identity and exit (requires -username/-pubkey/-ipv6)")
		username               = flag.String("username", "", "identity username for -add-user")
		pubkeyPath             = flag.String("pubkey", "", "path to SSH public key file for -add-user")
		ipv6Str                = flag.String("ipv6", "", "IPv6 address for -add-user")
		allowClaim             = flag.Bool("allow-claim", true, "allow first-come claim for unknown usernames (requires DNS env vars in production)")
		spoolDir               = flag.String("spool-dir", "/var/spool/sisumail", "Tier 2 ciphertext spool root (for delivery on reconnect)")
		chatSpoolDir           = flag.String("chat-spool-dir", "/var/spool/sisumail/chat", "encrypted chat queue root (for offline delivery)")
		chatMaxBytes           = flag.Int64("chat-max-bytes", 64<<10, "max encrypted chat payload bytes per message")
		chatLookupPerMin       = flag.Int("chat-lookup-per-min", 120, "max key-lookup requests per source IP per minute")
		chatSendPerMin         = flag.Int("chat-send-per-min", 240, "max chat-send requests per source IP per minute")
		chatSendPerUserPerMin  = flag.Int("chat-send-per-user-per-min", 120, "max chat-send requests per sender username per minute")
		chatReadTimeoutMS      = flag.Int("chat-read-timeout-ms", 5000, "chat channel read/header timeout in milliseconds")
		chatForwardTimeoutMS   = flag.Int("chat-forward-timeout-ms", 5000, "chat forward/copy timeout in milliseconds")
		acmeDNS01PerMin        = flag.Int("acme-dns01-per-user-per-min", 30, "max ACME DNS-01 control operations per user per minute")
		obsListen              = flag.String("obs-listen", "", "observability HTTP listen address (disabled when empty), e.g. 127.0.0.1:9090")
		obsReadHeaderTimeoutMS = flag.Int("obs-read-header-timeout-ms", 5000, "observability HTTP read-header timeout in milliseconds")
	)
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	store, err := identity.Open(*dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer store.Close()
	if err := store.Init(ctx); err != nil {
		log.Fatalf("init db: %v", err)
	}

	if *initDB {
		log.Printf("db initialized: %s", *dbPath)
		return
	}

	if *addUser {
		if *username == "" || *pubkeyPath == "" || *ipv6Str == "" {
			log.Fatalf("-add-user requires -username, -pubkey, -ipv6")
		}
		pkBytes, err := os.ReadFile(*pubkeyPath)
		if err != nil {
			log.Fatalf("read pubkey: %v", err)
		}
		ip := net.ParseIP(*ipv6Str)
		if ip == nil {
			log.Fatalf("invalid ipv6: %s", *ipv6Str)
		}
		if err := store.Put(ctx, *username, string(pkBytes), ip); err != nil {
			log.Fatalf("put identity: %v", err)
		}
		log.Printf("identity upserted: %s -> %s", *username, ip.String())
		return
	}

	reg := relay.NewSessionRegistry()
	// Load known dest IPv6 -> username map into memory for Tier 1 routing.
	ids, err := store.All(ctx)
	if err != nil && err != sql.ErrNoRows {
		log.Fatalf("load identities: %v", err)
	}
	for _, id := range ids {
		reg.SetUserDestIPv6(id.Username, id.IPv6)
	}

	// DNS provisioner (optional; required for production auto-claim).
	prov, ipv6Prefix := loadProvisioningFromEnv()
	var acmeCtrl *acmeDNS01Controller
	if prov != nil && prov.DNS != nil && strings.TrimSpace(prov.ZoneName) != "" {
		acmeCtrl = newACMEDNS01Controller(prov.ZoneName, prov.DNS, *acmeDNS01PerMin)
	}

	// Dev SSH server: accepts any pubkey, binds by SSH username.
	hostKey, err := loadOrCreateHostKey(*hostKeyPath)
	if err != nil {
		log.Fatalf("host key: %v", err)
	}
	serverCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(connMeta ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			u := strings.TrimSpace(connMeta.User())
			if u == "" {
				return nil, fmt.Errorf("missing username")
			}
			if isReservedUsername(u) {
				return nil, fmt.Errorf("reserved username")
			}
			// Dev override: allow any key for the dev user to reduce setup friction.
			// For production, remove this and require a provisioned identity.
			if *devUser != "" && u == *devUser {
				return &ssh.Permissions{Extensions: map[string]string{"identity_status": "dev-user"}}, nil
			}

			id, err := store.GetByUsername(ctx, u)
			if err != nil {
				return nil, fmt.Errorf("db error")
			}
			if id == nil {
				if !*allowClaim {
					return nil, fmt.Errorf("unknown user")
				}
				if prov == nil || ipv6Prefix == nil {
					return nil, fmt.Errorf("unknown user (claim disabled: missing DNS env)")
				}
				claimed, isNew, err := store.Claim(ctx, u, pubKey, ipv6Prefix)
				if err != nil {
					log.Printf("claim error: user=%s remote=%s err=%v", u, connMeta.RemoteAddr(), err)
					return nil, fmt.Errorf("claim failed")
				}
				if isNew {
					if err := prov.ProvisionUser(u, claimed.IPv6); err != nil {
						log.Printf("provision error: user=%s ip=%s err=%v", u, claimed.IPv6.String(), err)
						_ = store.DeleteByUsername(ctx, u)
						return nil, fmt.Errorf("provision failed")
					}
					reg.SetUserDestIPv6(u, claimed.IPv6)
					log.Printf("claimed identity: %s -> %s", u, claimed.IPv6.String())
				}
				return &ssh.Permissions{Extensions: map[string]string{"identity_status": "claimed-new"}}, nil
			}
			if subtle.ConstantTimeCompare(id.PubKey.Marshal(), pubKey.Marshal()) != 1 {
				return nil, fmt.Errorf("wrong key")
			}
			return &ssh.Permissions{Extensions: map[string]string{"identity_status": "existing"}}, nil
		},
	}
	serverCfg.AddHostKey(hostKey)

	spool := &tier2.FileSpool{Root: *spoolDir}
	chatSpool := &chatqueue.Store{Root: *chatSpoolDir}
	spoolPump := newSpoolDeliveryPump()
	stats := observability.NewRelayStats()
	ready := &relayReadiness{}
	tier1Obs := &tier1MetricsObserver{stats: stats, ready: ready}
	chatGuard := newChatGuard(chatGuardConfig{
		MaxBytes:          *chatMaxBytes,
		LookupPerMinute:   *chatLookupPerMin,
		SendPerMinuteIP:   *chatSendPerMin,
		SendPerMinuteUser: *chatSendPerUserPerMin,
		ReadTimeout:       time.Duration(*chatReadTimeoutMS) * time.Millisecond,
		ForwardTimeout:    time.Duration(*chatForwardTimeoutMS) * time.Millisecond,
	})

	go func() {
		if err := runSSHGateway(ctx, *sshListen, serverCfg, store, reg, spool, chatSpool, chatGuard, spoolPump, acmeCtrl, stats, ready.setSSHListening); err != nil {
			log.Printf("ssh gateway error: %v", err)
			cancel()
		}
	}()
	go runSpoolNotifyLoop(ctx, reg, spool, spoolPump, stats)

	proxy := &relay.Tier1Proxy{
		ListenAddr:         *tier1Listen,
		Registry:           reg,
		DevRouteUser:       *devUser,
		FastFail:           time.Duration(*tier1FastFailMS) * time.Millisecond,
		ChannelOpenTimeout: time.Duration(*tier1OpenTimeoutMS) * time.Millisecond,
		IdleTimeout:        time.Duration(*tier1IdleTimeoutMS) * time.Millisecond,
		MaxConnDuration:    time.Duration(*tier1MaxConnDurationMS) * time.Millisecond,
		MaxBytesPerConn:    *tier1MaxBytesPerConn,
		MaxConnsPerUser:    *tier1MaxPerUser,
		MaxConnsPerSource:  *tier1MaxPerSource,
		Observer:           tier1Obs,
		ResolveUser: func(destIP net.IP) (string, bool) {
			return reg.GetUserByDestIPv6(destIP)
		},
	}
	go func() {
		if err := proxy.Run(ctx); err != nil {
			log.Printf("tier1 proxy error: %v", err)
			cancel()
		}
	}()

	if strings.TrimSpace(*obsListen) != "" {
		go func() {
			if err := runObservabilityServer(ctx, *obsListen, stats, ready.status, time.Duration(*obsReadHeaderTimeoutMS)*time.Millisecond); err != nil {
				log.Printf("observability server error: %v", err)
				cancel()
			}
		}()
	}

	<-ctx.Done()
}

func loadProvisioningFromEnv() (*provision.Provisioner, *net.IPNet) {
	// Hetzner Console (Cloud API) token. This is NOT the deprecated dns.hetzner.com token.
	// Accept both names for operator convenience.
	token := strings.TrimSpace(os.Getenv("HCLOUD_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("HETZNER_CLOUD_TOKEN"))
	}
	zone := strings.TrimSpace(os.Getenv("SISUMAIL_DNS_ZONE"))
	prefixStr := strings.TrimSpace(os.Getenv("SISUMAIL_IPV6_PREFIX"))
	if token == "" || zone == "" || prefixStr == "" {
		return nil, nil
	}
	_, ipnet, err := net.ParseCIDR(prefixStr)
	if err != nil {
		log.Printf("invalid SISUMAIL_IPV6_PREFIX: %v", err)
		return nil, nil
	}
	dns := hetznercloud.NewClient(token, zone)
	return &provision.Provisioner{DNS: dns, ZoneName: zone}, ipnet
}

func isReservedUsername(u string) bool {
	u = strings.ToLower(strings.TrimSpace(u))
	if u == "" {
		return true
	}
	// Conservative v1 reserved list (aligns with whitepaper's intent).
	switch u {
	case "admin", "postmaster", "abuse", "hostmaster", "webmaster", "mailer-daemon",
		"root", "security", "support", "info", "contact", "noreply", "no-reply",
		"www", "ftp", "mail", "smtp", "imap", "pop", "ns1", "ns2", "mx", "mta-sts",
		"spool", "v6":
		return true
	}
	// Also reserve numeric-only names to avoid collisions with internal address conventions.
	if _, err := strconv.Atoi(u); err == nil {
		return true
	}
	return false
}

func runSSHGateway(ctx context.Context, addr string, cfg *ssh.ServerConfig, store *identity.Store, reg *relay.SessionRegistry, spool *tier2.FileSpool, chatSpool *chatqueue.Store, chatGuard *chatGuard, pump *spoolDeliveryPump, acmeCtrl *acmeDNS01Controller, stats *observability.RelayStats, onListening func()) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	log.Printf("ssh gateway listening on %s", addr)
	if onListening != nil {
		onListening()
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		nc, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			return err
		}
		go handleSSHConn(ctx, nc, cfg, store, reg, spool, chatSpool, chatGuard, pump, acmeCtrl, stats)
	}
}

func handleSSHConn(ctx context.Context, nc net.Conn, cfg *ssh.ServerConfig, store *identity.Store, reg *relay.SessionRegistry, spool *tier2.FileSpool, chatSpool *chatqueue.Store, chatGuard *chatGuard, pump *spoolDeliveryPump, acmeCtrl *acmeDNS01Controller, stats *observability.RelayStats) {
	defer nc.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	defer sshConn.Close()

	user := strings.TrimSpace(sshConn.User())
	if user == "" {
		return
	}
	source := remoteIPString(sshConn.RemoteAddr())
	identityStatus := "existing"
	if sshConn.Permissions != nil && sshConn.Permissions.Extensions != nil {
		if s := strings.TrimSpace(sshConn.Permissions.Extensions["identity_status"]); s != "" {
			identityStatus = s
		}
	}
	if store != nil {
		store.TouchLastSeen(context.Background(), user)
	}

	reg.SetSession(user, &relay.Session{Username: user, Conn: sshConn})
	if stats != nil {
		stats.IncSSHSessions(1)
	}
	log.Printf("ssh session registered: user=%s remote=%s", user, sshConn.RemoteAddr())
	defer func() {
		reg.DeleteSession(user)
		if stats != nil {
			stats.IncSSHSessions(-1)
		}
		log.Printf("ssh session deregistered: user=%s", user)
	}()

	// Deliver any pending Tier 2 spool entries for this user (best-effort).
	// This keeps the "spool on reconnect" promise without requiring polling.
	if spool != nil && pump != nil {
		go deliverPendingSpool(ctx, sshConn, user, spool, pump, true, stats)
	}
	if chatSpool != nil {
		go deliverPendingChat(ctx, sshConn, user, chatSpool, true, stats)
	}

	// Ignore global requests.
	go ssh.DiscardRequests(reqs)

	// Accept client-opened channels.
	for {
		select {
		case <-ctx.Done():
			return
		case newCh, ok := <-chans:
			if !ok {
				return
			}
			go func(ch ssh.NewChannel) {
				switch ch.ChannelType() {
				case "session":
					c, reqs, err := ch.Accept()
					if err != nil {
						return
					}
					execLike := pollSessionRequests(reqs, 150*time.Millisecond)
					status := uint32(0)
					if !execLike {
						status = runHostedShell(c, hostedShellEnv{
							username:       user,
							source:         source,
							identityStatus: identityStatus,
							store:          store,
							reg:            reg,
							spool:          spool,
							chatSpool:      chatSpool,
							guard:          chatGuard,
							stats:          stats,
						})
					} else {
						_, _ = c.Write([]byte("exec/subsystem not supported; use interactive ssh session\n"))
						status = 1
					}
					_, _ = c.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: status}))
					_ = c.Close()
				case "key-lookup":
					handleKeyLookupChannel(ch, store, source, chatGuard, stats)
				case "chat-send":
					handleChatSendChannel(ch, user, source, reg, chatSpool, chatGuard, stats)
				case "acme-dns01":
					handleACMEDNS01Channel(ch, user, acmeCtrl)
				default:
					_ = ch.Reject(ssh.UnknownChannelType, "unsupported")
					return
				}
			}(newCh)
		}
	}
}

func handleKeyLookupChannel(ch ssh.NewChannel, store *identity.Store, source string, guard *chatGuard, stats *observability.RelayStats) {
	c, reqs, err := ch.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	defer c.Close()

	if guard != nil && !guard.allowLookup(source) {
		if stats != nil {
			stats.IncChatLookupLimited()
		}
		return
	}
	if stats != nil {
		stats.IncChatLookupTotal()
	}
	if store == nil {
		_ = proto.WriteKeyLookupResponse(c, "")
		return
	}
	u, err := readChatLookupRequestWithTimeout(c, guardReadTimeout(guard))
	if err != nil {
		return
	}
	if !isLookupUsernameAllowed(u) {
		_ = proto.WriteKeyLookupResponse(c, "")
		return
	}
	id, err := store.GetByUsername(context.Background(), u)
	if err != nil || id == nil {
		_ = proto.WriteKeyLookupResponse(c, "")
		return
	}
	_ = proto.WriteKeyLookupResponse(c, id.PubKeyText)
}

func handleChatSendChannel(ch ssh.NewChannel, sender string, source string, reg *relay.SessionRegistry, chatSpool *chatqueue.Store, guard *chatGuard, stats *observability.RelayStats) {
	c, reqs, err := ch.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	defer c.Close()

	if guard != nil && (!guard.allowSendBySource(source) || !guard.allowSendByUser(sender)) {
		if stats != nil {
			stats.IncChatSendLimited()
		}
		return
	}
	if stats != nil {
		stats.IncChatSendTotal()
	}
	h, br, err := readChatSendHeaderWithTimeout(c, guardReadTimeout(guard))
	if err != nil {
		return
	}
	if reg == nil || strings.TrimSpace(h.To) == "" || h.SizeBytes < 0 {
		return
	}
	if guard != nil && guard.maxBytes > 0 && h.SizeBytes > guard.maxBytes {
		return
	}
	ct, err := io.ReadAll(io.LimitReader(br, h.SizeBytes))
	if err != nil {
		return
	}
	if int64(len(ct)) != h.SizeBytes {
		return
	}
	_ = deliverOrQueueChatCiphertext(sender, h.To, bytes.NewReader(ct), h.SizeBytes, reg, chatSpool, stats)
}

func deliverOrQueueChatCiphertext(sender, to string, payload io.Reader, size int64, reg *relay.SessionRegistry, chatSpool *chatqueue.Store, stats *observability.RelayStats) error {
	if reg == nil || strings.TrimSpace(to) == "" || payload == nil || size < 0 {
		return fmt.Errorf("invalid chat delivery args")
	}
	ct, err := io.ReadAll(io.LimitReader(payload, size))
	if err != nil {
		return err
	}
	if int64(len(ct)) != size {
		return fmt.Errorf("chat payload size mismatch")
	}

	queue := func() error {
		if chatSpool == nil {
			return nil
		}
		id := fmt.Sprintf("%d", time.Now().UnixNano())
		meta := chatqueue.Meta{
			ID:         id,
			From:       sender,
			To:         to,
			ReceivedAt: time.Now(),
		}
		if err := chatSpool.Put(to, id, bytes.NewReader(ct), meta); err != nil {
			return err
		}
		if stats != nil {
			stats.IncChatQueuedOffline()
		}
		return nil
	}

	dst, ok := reg.GetSession(to)
	if !ok || dst == nil || dst.Conn == nil {
		return queue()
	}
	out, outReqs, err := dst.Conn.OpenChannel("chat-delivery", nil)
	if err != nil {
		return queue()
	}
	go ssh.DiscardRequests(outReqs)
	defer out.Close()
	id := fmt.Sprintf("%d", time.Now().UnixNano())
	dh := proto.ChatDeliveryHeader{From: sender, MessageID: id, SizeBytes: size}
	if err := proto.WriteChatDeliveryHeader(out, dh); err != nil {
		return queue()
	}
	if _, err := io.Copy(out, bytes.NewReader(ct)); err != nil {
		return queue()
	}
	if stats != nil {
		stats.IncChatDeliveredLive()
	}
	return nil
}

func handleACMEDNS01Channel(ch ssh.NewChannel, user string, ctrl *acmeDNS01Controller) {
	c, reqs, err := ch.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	defer c.Close()

	if ctrl == nil || !ctrl.enabled() {
		_ = proto.WriteACMEDNS01Response(c, proto.ACMEDNS01Response{OK: false, Message: "acme dns control unavailable"})
		return
	}
	req, err := proto.ReadACMEDNS01Request(c)
	if err != nil {
		_ = proto.WriteACMEDNS01Response(c, proto.ACMEDNS01Response{OK: false, Message: "bad request"})
		return
	}

	op := strings.ToUpper(strings.TrimSpace(req.Op))
	switch op {
	case "PRESENT":
		if err := ctrl.present(user, req.Hostname, req.Value); err != nil {
			_ = proto.WriteACMEDNS01Response(c, proto.ACMEDNS01Response{OK: false, Message: err.Error()})
			return
		}
	case "CLEANUP":
		if err := ctrl.cleanup(user, req.Hostname, req.Value); err != nil {
			_ = proto.WriteACMEDNS01Response(c, proto.ACMEDNS01Response{OK: false, Message: err.Error()})
			return
		}
	default:
		_ = proto.WriteACMEDNS01Response(c, proto.ACMEDNS01Response{OK: false, Message: "unsupported operation"})
		return
	}

	_ = proto.WriteACMEDNS01Response(c, proto.ACMEDNS01Response{OK: true})
}

func pollSessionRequests(reqs <-chan *ssh.Request, wait time.Duration) (execLike bool) {
	if wait <= 0 {
		wait = 150 * time.Millisecond
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()

	// First request: wait briefly for common ssh request patterns (exec/shell/pty).
	select {
	case req, ok := <-reqs:
		if ok && handleSessionRequest(req) {
			execLike = true
		}
	case <-timer.C:
	}

	// Drain any requests that are already queued without blocking.
	for {
		select {
		case req, ok := <-reqs:
			if !ok {
				return execLike
			}
			if handleSessionRequest(req) {
				execLike = true
			}
		default:
			return execLike
		}
	}
}

func handleSessionRequest(req *ssh.Request) (execLike bool) {
	if req == nil {
		return false
	}
	allow, isExecLike := sessionRequestAllowed(req.Type)
	if req.WantReply {
		_ = req.Reply(allow, nil)
	}
	return isExecLike
}

func sessionRequestAllowed(reqType string) (allow bool, execLike bool) {
	switch strings.TrimSpace(strings.ToLower(reqType)) {
	case "shell", "pty-req", "window-change":
		return true, false
	case "exec", "subsystem":
		return false, true
	default:
		return false, false
	}
}

type hostedShellEnv struct {
	username       string
	source         string
	identityStatus string
	store          *identity.Store
	reg            *relay.SessionRegistry
	spool          *tier2.FileSpool
	chatSpool      *chatqueue.Store
	guard          *chatGuard
	stats          *observability.RelayStats
}

func runHostedShell(ch ssh.Channel, env hostedShellEnv) uint32 {
	if ch == nil {
		return 1
	}
	in := bufio.NewReader(ch)
	_, _ = io.WriteString(ch, "Sisumail Hosted Shell\n")
	if env.identityStatus == "claimed-new" {
		_, _ = io.WriteString(ch, "identity claimed and bound to your SSH key\n")
	}
	_, _ = io.WriteString(ch, "Sisumail is receive-only identity mail + encrypted chat, not conversational outbound email.\n")
	_, _ = io.WriteString(ch, "Commands: ¤help, ¤whoami, ¤status, ¤lookup <user>, ¤chatq, ¤mailq, ¤quit\n")
	_, _ = io.WriteString(ch, "Quick chat send: ¤<user> <message>\n")
	for {
		_, _ = io.WriteString(ch, "¤ ")
		line, err := in.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return 0
			}
			return 1
		}
		kind, a, b := parseRelayShellDirective(line)
		switch kind {
		case "noop":
			continue
		case "quit":
			return 0
		case "help":
			_, _ = io.WriteString(ch, "Commands:\n")
			_, _ = io.WriteString(ch, "¤help\n¤whoami\n¤status\n¤lookup <user>\n¤chatq\n¤mailq\n¤quit\n")
			_, _ = io.WriteString(ch, "Quick chat send: ¤<user> <message>\n")
		case "whoami":
			_, _ = io.WriteString(ch, fmt.Sprintf("user=%s source=%s\n", env.username, env.source))
		case "status":
			chatQueued := 0
			if env.chatSpool != nil {
				if list, err := env.chatSpool.List(env.username); err == nil {
					chatQueued = len(list)
				}
			}
			mailQueued := 0
			if env.spool != nil {
				if list, err := env.spool.List(env.username); err == nil {
					mailQueued = len(list)
				}
			}
			_, _ = io.WriteString(ch, fmt.Sprintf("chat_queue=%d mail_queue=%d\n", chatQueued, mailQueued))
		case "lookup":
			target := strings.TrimSpace(a)
			if target == "" {
				_, _ = io.WriteString(ch, "usage: ¤lookup <user>\n")
				continue
			}
			id, err := env.lookup(target)
			if err != nil {
				_, _ = io.WriteString(ch, fmt.Sprintf("lookup failed: %v\n", err))
				continue
			}
			if id == nil {
				_, _ = io.WriteString(ch, "not found\n")
				continue
			}
			online := false
			if env.reg != nil {
				_, online = env.reg.GetSession(target)
			}
			_, _ = io.WriteString(ch, fmt.Sprintf("user=%s fp=%s online=%v\n", id.Username, id.Fingerprint, online))
		case "chatq":
			if env.chatSpool == nil {
				_, _ = io.WriteString(ch, "chat queue unavailable\n")
				continue
			}
			list, err := env.chatSpool.List(env.username)
			if err != nil {
				_, _ = io.WriteString(ch, fmt.Sprintf("chatq failed: %v\n", err))
				continue
			}
			_, _ = io.WriteString(ch, fmt.Sprintf("queued chat messages: %d\n", len(list)))
			for i := 0; i < len(list) && i < 10; i++ {
				m := list[i]
				_, _ = io.WriteString(ch, fmt.Sprintf("%s from=%s bytes=%d at=%s\n", m.ID, m.From, m.SizeBytes, m.ReceivedAt.UTC().Format(time.RFC3339)))
			}
		case "mailq":
			if env.spool == nil {
				_, _ = io.WriteString(ch, "mail queue unavailable\n")
				continue
			}
			list, err := env.spool.List(env.username)
			if err != nil {
				_, _ = io.WriteString(ch, fmt.Sprintf("mailq failed: %v\n", err))
				continue
			}
			_, _ = io.WriteString(ch, fmt.Sprintf("queued encrypted mail items: %d\n", len(list)))
			_, _ = io.WriteString(ch, "mail bodies stay encrypted; use local sisumail client to decrypt/read.\n")
		case "send":
			to := strings.TrimSpace(a)
			msg := strings.TrimSpace(b)
			if to == "" || msg == "" {
				_, _ = io.WriteString(ch, "usage: ¤<user> <message>\n")
				continue
			}
			if err := env.sendHostedChat(to, msg); err != nil {
				_, _ = io.WriteString(ch, fmt.Sprintf("send failed: %v\n", err))
				continue
			}
			_, _ = io.WriteString(ch, "sent\n")
		default:
			_, _ = io.WriteString(ch, "unknown command. type ¤help\n")
		}
	}
}

func (env hostedShellEnv) lookup(username string) (*identity.Identity, error) {
	if env.store == nil {
		return nil, fmt.Errorf("identity store unavailable")
	}
	u := strings.TrimSpace(strings.ToLower(username))
	if !isLookupUsernameAllowed(u) {
		return nil, fmt.Errorf("invalid username")
	}
	return env.store.GetByUsername(context.Background(), u)
}

func (env hostedShellEnv) sendHostedChat(to, message string) error {
	target, err := env.lookup(to)
	if err != nil {
		return err
	}
	if target == nil {
		return fmt.Errorf("unknown user")
	}
	if env.guard != nil && (!env.guard.allowSendBySource(env.source) || !env.guard.allowSendByUser(env.username)) {
		if env.stats != nil {
			env.stats.IncChatSendLimited()
		}
		return fmt.Errorf("rate limited")
	}
	if env.stats != nil {
		env.stats.IncChatSendTotal()
	}
	var ct bytes.Buffer
	if err := tier2.StreamEncrypt(&ct, strings.NewReader(message), target.PubKeyText); err != nil {
		return err
	}
	size := int64(ct.Len())
	if env.guard != nil && env.guard.maxBytes > 0 && size > env.guard.maxBytes {
		return fmt.Errorf("message too large")
	}
	return deliverOrQueueChatCiphertext(env.username, target.Username, bytes.NewReader(ct.Bytes()), size, env.reg, env.chatSpool, env.stats)
}

func parseRelayShellDirective(line string) (kind string, arg1 string, arg2 string) {
	s := strings.TrimSpace(line)
	if s == "" {
		return "noop", "", ""
	}
	if strings.HasPrefix(s, "/") {
		s = "¤" + strings.TrimPrefix(s, "/")
	}
	if !strings.HasPrefix(s, "¤") {
		return "unknown", "", ""
	}
	s = strings.TrimSpace(strings.TrimPrefix(s, "¤"))
	if s == "" {
		return "noop", "", ""
	}
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return "noop", "", ""
	}
	cmd := strings.ToLower(parts[0])
	switch cmd {
	case "q", "quit", "exit":
		return "quit", "", ""
	case "help", "h":
		return "help", "", ""
	case "whoami", "me":
		return "whoami", "", ""
	case "status", "s":
		return "status", "", ""
	case "lookup", "l":
		if len(parts) < 2 {
			return "lookup", "", ""
		}
		return "lookup", parts[1], ""
	case "chatq":
		return "chatq", "", ""
	case "mailq":
		return "mailq", "", ""
	default:
		if len(parts) < 2 {
			return "send", cmd, ""
		}
		msg := strings.TrimSpace(strings.TrimPrefix(s, parts[0]))
		return "send", cmd, msg
	}
}

func deliverPendingChat(ctx context.Context, chOpen relay.SSHChannelOpener, user string, q *chatqueue.Store, initialDelay bool, stats *observability.RelayStats) {
	if chOpen == nil || q == nil || strings.TrimSpace(user) == "" {
		return
	}
	list, err := q.List(user)
	if err != nil || len(list) == 0 {
		return
	}
	if initialDelay {
		time.Sleep(150 * time.Millisecond)
	}
	for _, meta := range list {
		select {
		case <-ctx.Done():
			return
		default:
		}
		rc, got, err := q.Get(user, meta.ID)
		if err != nil {
			continue
		}
		ch, reqs, err := chOpen.OpenChannel("chat-delivery", nil)
		if err != nil {
			_ = rc.Close()
			continue
		}
		go ssh.DiscardRequests(reqs)
		h := proto.ChatDeliveryHeader{From: got.From, MessageID: got.ID, SizeBytes: got.SizeBytes}
		if err := proto.WriteChatDeliveryHeader(ch, h); err != nil {
			_ = rc.Close()
			_ = ch.Close()
			continue
		}
		_, err = io.Copy(ch, rc)
		_ = rc.Close()
		if err != nil {
			_ = ch.Close()
			continue
		}
		ackCh := make(chan error, 1)
		go func() { ackCh <- proto.ReadChatAck(ch, got.ID) }()
		select {
		case err := <-ackCh:
			if err == nil {
				_ = q.Ack(user, meta.ID)
				if stats != nil {
					stats.IncChatAcked()
					stats.IncChatDeliveredFromQueue()
				}
			}
		case <-time.After(3 * time.Second):
			// Keep queued entry for retry on next reconnect.
		}
		_ = ch.Close()
	}
}

func remoteIPString(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil && strings.TrimSpace(host) != "" {
		return host
	}
	return addr.String()
}

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func isLookupUsernameAllowed(u string) bool {
	u = strings.TrimSpace(strings.ToLower(u))
	if !usernamePattern.MatchString(u) {
		return false
	}
	if isReservedUsername(u) {
		return false
	}
	return true
}

type chatGuardConfig struct {
	MaxBytes          int64
	LookupPerMinute   int
	SendPerMinuteIP   int
	SendPerMinuteUser int
	ReadTimeout       time.Duration
	ForwardTimeout    time.Duration
}

type chatGuard struct {
	maxBytes       int64
	readTimeout    time.Duration
	forwardTimeout time.Duration

	mu              sync.Mutex
	lookupBySource  map[string]*rateWindow
	sendBySource    map[string]*rateWindow
	sendByUser      map[string]*rateWindow
	lookupLimit     int
	sendSourceLimit int
	sendUserLimit   int
}

type rateWindow struct {
	start time.Time
	count int
}

func newChatGuard(cfg chatGuardConfig) *chatGuard {
	return &chatGuard{
		maxBytes:        cfg.MaxBytes,
		readTimeout:     cfg.ReadTimeout,
		forwardTimeout:  cfg.ForwardTimeout,
		lookupBySource:  make(map[string]*rateWindow),
		sendBySource:    make(map[string]*rateWindow),
		sendByUser:      make(map[string]*rateWindow),
		lookupLimit:     cfg.LookupPerMinute,
		sendSourceLimit: cfg.SendPerMinuteIP,
		sendUserLimit:   cfg.SendPerMinuteUser,
	}
}

func (g *chatGuard) allowLookup(source string) bool {
	return g.allow(g.lookupBySource, source, g.lookupLimit)
}

func (g *chatGuard) allowSendBySource(source string) bool {
	return g.allow(g.sendBySource, source, g.sendSourceLimit)
}

func (g *chatGuard) allowSendByUser(user string) bool {
	return g.allow(g.sendByUser, strings.ToLower(strings.TrimSpace(user)), g.sendUserLimit)
}

func (g *chatGuard) allow(m map[string]*rateWindow, key string, limit int) bool {
	if g == nil || limit <= 0 {
		return true
	}
	key = strings.TrimSpace(key)
	if key == "" {
		key = "unknown"
	}
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	w, ok := m[key]
	if !ok || now.Sub(w.start) >= time.Minute {
		m[key] = &rateWindow{start: now, count: 1}
		return true
	}
	if w.count >= limit {
		return false
	}
	w.count++
	return true
}

func guardReadTimeout(g *chatGuard) time.Duration {
	if g == nil || g.readTimeout <= 0 {
		return 5 * time.Second
	}
	return g.readTimeout
}

func guardForwardTimeout(g *chatGuard) time.Duration {
	if g == nil || g.forwardTimeout <= 0 {
		return 5 * time.Second
	}
	return g.forwardTimeout
}

func readChatLookupRequestWithTimeout(r io.Reader, timeout time.Duration) (string, error) {
	type res struct {
		u   string
		err error
	}
	ch := make(chan res, 1)
	go func() {
		u, err := proto.ReadKeyLookupRequest(r)
		ch <- res{u: u, err: err}
	}()
	select {
	case out := <-ch:
		return out.u, out.err
	case <-time.After(timeout):
		return "", fmt.Errorf("lookup read timeout")
	}
}

func readChatSendHeaderWithTimeout(r io.Reader, timeout time.Duration) (proto.ChatSendHeader, *bufio.Reader, error) {
	type res struct {
		h   proto.ChatSendHeader
		br  *bufio.Reader
		err error
	}
	ch := make(chan res, 1)
	go func() {
		h, br, err := proto.ReadChatSendHeader(r)
		ch <- res{h: h, br: br, err: err}
	}()
	select {
	case out := <-ch:
		return out.h, out.br, out.err
	case <-time.After(timeout):
		return proto.ChatSendHeader{}, nil, fmt.Errorf("chat header read timeout")
	}
}

func copyNWithTimeout(dst io.Writer, src io.Reader, n int64, timeout time.Duration) (int64, error) {
	type res struct {
		n   int64
		err error
	}
	ch := make(chan res, 1)
	go func() {
		w, err := io.CopyN(dst, src, n)
		ch <- res{n: w, err: err}
	}()
	select {
	case out := <-ch:
		return out.n, out.err
	case <-time.After(timeout):
		return 0, fmt.Errorf("copy timeout")
	}
}

func runSpoolNotifyLoop(ctx context.Context, reg *relay.SessionRegistry, spool *tier2.FileSpool, pump *spoolDeliveryPump, stats *observability.RelayStats) {
	if reg == nil || spool == nil || pump == nil {
		return
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			users := reg.OnlineUsers()
			for _, user := range users {
				sess, ok := reg.GetSession(user)
				if !ok || sess == nil || sess.Conn == nil {
					continue
				}
				go deliverPendingSpool(ctx, sess.Conn, user, spool, pump, false, stats)
			}
		}
	}
}

func deliverPendingSpool(ctx context.Context, chOpen relay.SSHChannelOpener, user string, spool *tier2.FileSpool, pump *spoolDeliveryPump, initialDelay bool, stats *observability.RelayStats) {
	if chOpen == nil || user == "" || spool == nil || pump == nil {
		return
	}
	if !pump.tryLock(user) {
		return
	}
	defer pump.unlock(user)

	list, err := spool.List(user)
	if err != nil || len(list) == 0 {
		return
	}
	// Small delay to let the client set up channel handlers on fresh connect.
	if initialDelay {
		time.Sleep(150 * time.Millisecond)
	}

	for _, meta := range list {
		select {
		case <-ctx.Done():
			return
		default:
		}
		rc, gotMeta, err := spool.Get(user, meta.MessageID)
		if err != nil {
			continue
		}

		ch, reqs, err := chOpen.OpenChannel("spool-delivery", nil)
		if err != nil {
			_ = rc.Close()
			continue
		}
		go ssh.DiscardRequests(reqs)

		h := proto.SpoolDeliveryHeader{MessageID: meta.MessageID, SizeBytes: gotMeta.SizeBytes}
		if err := proto.WriteSpoolDeliveryHeader(ch, h); err != nil {
			_ = rc.Close()
			_ = ch.Close()
			continue
		}

		_, copyErr := io.Copy(ch, rc)
		_ = rc.Close()
		if copyErr != nil {
			_ = ch.Close()
			continue
		}

		// Wait for ACK, then delete from spool.
		ackCh := make(chan error, 1)
		go func() { ackCh <- proto.ReadSpoolAck(ch, meta.MessageID) }()
		select {
		case err := <-ackCh:
			if err == nil {
				_ = spool.Ack(user, meta.MessageID)
				if stats != nil {
					stats.IncSpoolDelivered()
					stats.IncSpoolAcked()
				}
			}
		case <-time.After(3 * time.Second):
			// Best-effort; client may be offline/slow. Keep the spool entry.
		}
		_ = ch.Close()
	}
}

type spoolDeliveryPump struct {
	mu       sync.Mutex
	inFlight map[string]struct{}
}

func newSpoolDeliveryPump() *spoolDeliveryPump {
	return &spoolDeliveryPump{inFlight: make(map[string]struct{})}
}

func (p *spoolDeliveryPump) tryLock(user string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.inFlight[user]; exists {
		return false
	}
	p.inFlight[user] = struct{}{}
	return true
}

func (p *spoolDeliveryPump) unlock(user string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.inFlight, user)
}

func loadOrCreateHostKey(path string) (ssh.Signer, error) {
	// Try load first.
	if b, err := os.ReadFile(path); err == nil {
		return ssh.ParsePrivateKey(b)
	}

	// Create parent dir.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	// Generate Ed25519 key and serialize in OpenSSH format.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "sisumail-relay")
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(block)

	// Write with strict permissions.
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}

	return ssh.ParsePrivateKey(pemBytes)
}
