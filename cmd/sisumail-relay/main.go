package main

import (
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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sisumail/sisumail/internal/dns/hetznercloud"
	"github.com/sisumail/sisumail/internal/identity"
	"github.com/sisumail/sisumail/internal/provision"
	"github.com/sisumail/sisumail/internal/proto"
	"github.com/sisumail/sisumail/internal/relay"
	"github.com/sisumail/sisumail/internal/store/chatqueue"
	"github.com/sisumail/sisumail/internal/tier2"
	"golang.org/x/crypto/ssh"
)

func main() {
	var (
		sshListen   = flag.String("ssh-listen", ":2222", "SSH gateway listen address (dev default :2222)")
		tier1Listen = flag.String("tier1-listen", ":2525", "Tier 1 TCP proxy listen address (dev default :2525)")
		tier1FastFailMS = flag.Int("tier1-fast-fail-ms", 200, "Tier 1 fast-fail timeout in milliseconds")
		tier1OpenTimeoutMS = flag.Int("tier1-open-timeout-ms", 3000, "Tier 1 SSH channel-open timeout in milliseconds")
		tier1IdleTimeoutMS = flag.Int("tier1-idle-timeout-ms", 120000, "Tier 1 idle I/O timeout in milliseconds")
		tier1MaxPerUser = flag.Int("tier1-max-conns-per-user", 10, "Tier 1 max concurrent connections per user")
		tier1MaxPerSource = flag.Int("tier1-max-conns-per-source", 20, "Tier 1 max concurrent connections per source IP")
		devUser     = flag.String("dev-user", "", "dev-only: route all Tier 1 traffic to this username (empty disables)")
		hostKeyPath = flag.String("hostkey", "./data/relay_hostkey_ed25519", "path to relay SSH host key (created if missing)")
		dbPath      = flag.String("db", "./data/relay.db", "identity registry sqlite path")
		initDB      = flag.Bool("init-db", false, "initialize database schema and exit")
		addUser     = flag.Bool("add-user", false, "add/update an identity and exit (requires -username/-pubkey/-ipv6)")
		username    = flag.String("username", "", "identity username for -add-user")
		pubkeyPath  = flag.String("pubkey", "", "path to SSH public key file for -add-user")
		ipv6Str     = flag.String("ipv6", "", "IPv6 address for -add-user")
		allowClaim  = flag.Bool("allow-claim", true, "allow first-come claim for unknown usernames (requires DNS env vars in production)")
		spoolDir    = flag.String("spool-dir", "/var/spool/sisumail", "Tier 2 ciphertext spool root (for delivery on reconnect)")
		chatSpoolDir = flag.String("chat-spool-dir", "/var/spool/sisumail/chat", "encrypted chat queue root (for offline delivery)")
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
				return &ssh.Permissions{}, nil
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
				return &ssh.Permissions{}, nil
			}
			if subtle.ConstantTimeCompare(id.PubKey.Marshal(), pubKey.Marshal()) != 1 {
				return nil, fmt.Errorf("wrong key")
			}
			return &ssh.Permissions{}, nil
		},
	}
	serverCfg.AddHostKey(hostKey)

	spool := &tier2.FileSpool{Root: *spoolDir}
	chatSpool := &chatqueue.Store{Root: *chatSpoolDir}
	spoolPump := newSpoolDeliveryPump()

	go func() {
		if err := runSSHGateway(ctx, *sshListen, serverCfg, store, reg, spool, chatSpool, spoolPump); err != nil {
			log.Printf("ssh gateway error: %v", err)
			cancel()
		}
	}()
	go runSpoolNotifyLoop(ctx, reg, spool, spoolPump)

	proxy := &relay.Tier1Proxy{
		ListenAddr:         *tier1Listen,
		Registry:           reg,
		DevRouteUser:       *devUser,
		FastFail:           time.Duration(*tier1FastFailMS) * time.Millisecond,
		ChannelOpenTimeout: time.Duration(*tier1OpenTimeoutMS) * time.Millisecond,
		IdleTimeout:        time.Duration(*tier1IdleTimeoutMS) * time.Millisecond,
		MaxConnsPerUser:    *tier1MaxPerUser,
		MaxConnsPerSource:  *tier1MaxPerSource,
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

func runSSHGateway(ctx context.Context, addr string, cfg *ssh.ServerConfig, store *identity.Store, reg *relay.SessionRegistry, spool *tier2.FileSpool, chatSpool *chatqueue.Store, pump *spoolDeliveryPump) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	log.Printf("ssh gateway listening on %s", addr)

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
		go handleSSHConn(ctx, nc, cfg, store, reg, spool, chatSpool, pump)
	}
}

func handleSSHConn(ctx context.Context, nc net.Conn, cfg *ssh.ServerConfig, store *identity.Store, reg *relay.SessionRegistry, spool *tier2.FileSpool, chatSpool *chatqueue.Store, pump *spoolDeliveryPump) {
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

	reg.SetSession(user, &relay.Session{Username: user, Conn: sshConn})
	log.Printf("ssh session registered: user=%s remote=%s", user, sshConn.RemoteAddr())
	defer func() {
		reg.DeleteSession(user)
		log.Printf("ssh session deregistered: user=%s", user)
	}()

	// Deliver any pending Tier 2 spool entries for this user (best-effort).
	// This keeps the "spool on reconnect" promise without requiring polling.
	if spool != nil && pump != nil {
		go deliverPendingSpool(ctx, sshConn, user, spool, pump, true)
	}
	if chatSpool != nil {
		go deliverPendingChat(ctx, sshConn, user, chatSpool, true)
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
					go ssh.DiscardRequests(reqs)
					_, _ = c.Write([]byte("sisumail relay dev gateway (no TUI yet)\n"))
					_ = c.Close()
				case "key-lookup":
					handleKeyLookupChannel(ch, store)
				case "chat-send":
					handleChatSendChannel(ch, user, reg, chatSpool)
				default:
					_ = ch.Reject(ssh.UnknownChannelType, "unsupported")
					return
				}
			}(newCh)
		}
	}
}

func handleKeyLookupChannel(ch ssh.NewChannel, store *identity.Store) {
	c, reqs, err := ch.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	defer c.Close()

	if store == nil {
		_ = proto.WriteKeyLookupResponse(c, "")
		return
	}
	u, err := proto.ReadKeyLookupRequest(c)
	if err != nil {
		return
	}
	id, err := store.GetByUsername(context.Background(), u)
	if err != nil || id == nil {
		_ = proto.WriteKeyLookupResponse(c, "")
		return
	}
	_ = proto.WriteKeyLookupResponse(c, id.PubKeyText)
}

func handleChatSendChannel(ch ssh.NewChannel, sender string, reg *relay.SessionRegistry, chatSpool *chatqueue.Store) {
	c, reqs, err := ch.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	defer c.Close()

	h, br, err := proto.ReadChatSendHeader(c)
	if err != nil {
		return
	}
	if reg == nil || strings.TrimSpace(h.To) == "" || h.SizeBytes < 0 {
		return
	}
	dst, ok := reg.GetSession(h.To)
	if !ok || dst == nil || dst.Conn == nil {
		// Recipient offline: queue encrypted payload for later delivery.
		if chatSpool != nil {
			id := fmt.Sprintf("%d", time.Now().UnixNano())
			meta := chatqueue.Meta{
				ID:         id,
				From:       sender,
				To:         h.To,
				ReceivedAt: time.Now(),
			}
			_ = chatSpool.Put(h.To, id, io.LimitReader(br, h.SizeBytes), meta)
		}
		return
	}

	out, outReqs, err := dst.Conn.OpenChannel("chat-delivery", nil)
	if err != nil {
		// Best effort fallback to queue when live open fails.
		if chatSpool != nil {
			id := fmt.Sprintf("%d", time.Now().UnixNano())
			meta := chatqueue.Meta{
				ID:         id,
				From:       sender,
				To:         h.To,
				ReceivedAt: time.Now(),
			}
			_ = chatSpool.Put(h.To, id, io.LimitReader(br, h.SizeBytes), meta)
		}
		return
	}
	go ssh.DiscardRequests(outReqs)
	defer out.Close()

	id := fmt.Sprintf("%d", time.Now().UnixNano())
	dh := proto.ChatDeliveryHeader{From: sender, MessageID: id, SizeBytes: h.SizeBytes}
	if err := proto.WriteChatDeliveryHeader(out, dh); err != nil {
		return
	}
	_, _ = io.CopyN(out, br, h.SizeBytes)
}

func deliverPendingChat(ctx context.Context, chOpen relay.SSHChannelOpener, user string, q *chatqueue.Store, initialDelay bool) {
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
			}
		case <-time.After(3 * time.Second):
			// Keep queued entry for retry on next reconnect.
		}
		_ = ch.Close()
	}
}

func runSpoolNotifyLoop(ctx context.Context, reg *relay.SessionRegistry, spool *tier2.FileSpool, pump *spoolDeliveryPump) {
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
				go deliverPendingSpool(ctx, sess.Conn, user, spool, pump, false)
			}
		}
	}
}

func deliverPendingSpool(ctx context.Context, chOpen relay.SSHChannelOpener, user string, spool *tier2.FileSpool, pump *spoolDeliveryPump, initialDelay bool) {
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
