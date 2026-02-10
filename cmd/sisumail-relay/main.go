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
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sisumail/sisumail/internal/dns/hetznercloud"
	"github.com/sisumail/sisumail/internal/identity"
	"github.com/sisumail/sisumail/internal/provision"
	"github.com/sisumail/sisumail/internal/relay"
	"golang.org/x/crypto/ssh"
)

func main() {
	var (
		sshListen   = flag.String("ssh-listen", ":2222", "SSH gateway listen address (dev default :2222)")
		tier1Listen = flag.String("tier1-listen", ":2525", "Tier 1 TCP proxy listen address (dev default :2525)")
		devUser     = flag.String("dev-user", "", "dev-only: route all Tier 1 traffic to this username (empty disables)")
		hostKeyPath = flag.String("hostkey", "./data/relay_hostkey_ed25519", "path to relay SSH host key (created if missing)")
		dbPath      = flag.String("db", "./data/relay.db", "identity registry sqlite path")
		initDB      = flag.Bool("init-db", false, "initialize database schema and exit")
		addUser     = flag.Bool("add-user", false, "add/update an identity and exit (requires -username/-pubkey/-ipv6)")
		username    = flag.String("username", "", "identity username for -add-user")
		pubkeyPath  = flag.String("pubkey", "", "path to SSH public key file for -add-user")
		ipv6Str     = flag.String("ipv6", "", "IPv6 address for -add-user")
		allowClaim  = flag.Bool("allow-claim", true, "allow first-come claim for unknown usernames (requires DNS env vars in production)")
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

	go func() {
		if err := runSSHGateway(ctx, *sshListen, serverCfg, reg); err != nil {
			log.Printf("ssh gateway error: %v", err)
			cancel()
		}
	}()

	proxy := &relay.Tier1Proxy{
		ListenAddr:   *tier1Listen,
		Registry:     reg,
		DevRouteUser: *devUser,
		FastFail:     200 * time.Millisecond,
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

func runSSHGateway(ctx context.Context, addr string, cfg *ssh.ServerConfig, reg *relay.SessionRegistry) error {
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
		go handleSSHConn(ctx, nc, cfg, reg)
	}
}

func handleSSHConn(ctx context.Context, nc net.Conn, cfg *ssh.ServerConfig, reg *relay.SessionRegistry) {
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

	// Ignore global requests.
	go ssh.DiscardRequests(reqs)

	// Minimal dev behavior: accept "session" channels and write a banner, then close.
	// The important part is that the connection stays open to allow the server to open
	// "smtp-delivery" channels to the client.
	for {
		select {
		case <-ctx.Done():
			return
		case newCh, ok := <-chans:
			if !ok {
				return
			}
			go func(ch ssh.NewChannel) {
				if ch.ChannelType() != "session" {
					_ = ch.Reject(ssh.UnknownChannelType, "unsupported")
					return
				}
				c, reqs, err := ch.Accept()
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				_, _ = c.Write([]byte("sisumail relay dev gateway (no TUI yet)\n"))
				_ = c.Close()
			}(newCh)
		}
	}
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
