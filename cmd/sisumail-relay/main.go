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
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
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
		allowClaim             = flag.Bool("allow-claim", false, "allow first-come claim for unknown usernames (requires DNS env vars in production)")
		mintInvites            = flag.Bool("mint-invites", false, "operator: mint root invite codes and print them to stdout (requires SISUMAIL_INVITE_PEPPER in production)")
		mintInvitesN           = flag.Int("mint-invites-n", 1, "operator: number of root invite codes to mint when -mint-invites is set")
		claimPerSourcePerHour  = flag.Int("claim-per-source-per-hour", 3, "max new identity claims per source bucket per hour (0 disables)")
		claimPerSourcePerDay   = flag.Int("claim-per-source-per-day", 12, "max new identity claims per source bucket per day (0 disables)")
		claimGlobalPerHour     = flag.Int("claim-global-per-hour", 200, "max new identity claims globally per hour (0 disables)")
		claimGlobalPerDay      = flag.Int("claim-global-per-day", 1000, "max new identity claims globally per day (0 disables)")
		claimLogRetentionDays  = flag.Int("claim-log-retention-days", 30, "days to retain claim log rows for rate limiting (0 disables pruning)")
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
		wellKnownListen        = flag.String("well-known-listen", "", "public discovery HTTP listen address (disabled when empty), e.g. :8080")
		wellKnownPath          = flag.String("well-known-path", "/.well-known/sisu-node", "HTTP path for discovery document")
		wellKnownFile          = flag.String("well-known-file", "", "path to JSON document served at -well-known-path (required when -well-known-listen is set)")
		doctor               = flag.Bool("doctor", false, "print production readiness checks and exit")
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

	if *doctor {
		code := runRelayDoctor(*dbPath)
		if code != 0 {
			os.Exit(code)
		}
		return
	}

	if *mintInvites {
		pepper := strings.TrimSpace(os.Getenv("SISUMAIL_INVITE_PEPPER"))
		codes, err := store.MintRootInvites(ctx, *mintInvitesN, pepper)
		if err != nil {
			log.Fatalf("mint invites: %v", err)
		}
		for _, c := range codes {
			fmt.Println(c)
		}
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
	claimLimits := identity.ClaimLimits{
		PerSourcePerHour: *claimPerSourcePerHour,
		PerSourcePerDay:  *claimPerSourcePerDay,
		GlobalPerHour:    *claimGlobalPerHour,
		GlobalPerDay:     *claimGlobalPerDay,
		RetentionDays:    *claimLogRetentionDays,
	}
	serverCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(connMeta ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			raw := strings.TrimSpace(connMeta.User())
			// Bootstrap user for invite-only onboarding: accepts any key but only gets claim-v1 channel.
			if raw == "claim" {
				return &ssh.Permissions{Extensions: map[string]string{
					"identity_status":    "bootstrap",
					"canonical_username": "claim",
				}}, nil
			}
			u, err := identity.CanonicalUsername(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid username")
			}
			if isReservedUsername(u) {
				return nil, fmt.Errorf("reserved username")
			}
			// Dev override: allow any key for the dev user to reduce setup friction.
			// For production, remove this and require a provisioned identity.
			if *devUser != "" && u == *devUser {
				return &ssh.Permissions{Extensions: map[string]string{
					"identity_status":    "dev-user",
					"canonical_username": u,
				}}, nil
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
				bucket := sourceBucket(connMeta.RemoteAddr())
				claimed, isNew, err := store.Claim(ctx, u, pubKey, ipv6Prefix, bucket, claimLimits)
				if err != nil {
					log.Printf("claim error: user=%s remote=%s err=%v", u, connMeta.RemoteAddr(), err)
					if errors.Is(err, identity.ErrClaimRateLimited) {
						return nil, fmt.Errorf("claim rate limited")
					}
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
					return &ssh.Permissions{Extensions: map[string]string{
						"identity_status":    "claimed-new",
						"canonical_username": u,
					}}, nil
				}
				return &ssh.Permissions{Extensions: map[string]string{
					"identity_status":    "existing",
					"canonical_username": u,
				}}, nil
			}
			if subtle.ConstantTimeCompare(id.PubKey.Marshal(), pubKey.Marshal()) != 1 {
				return nil, fmt.Errorf("wrong key")
			}
			return &ssh.Permissions{Extensions: map[string]string{
				"identity_status":    "existing",
				"canonical_username": u,
			}}, nil
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
		if err := runSSHGateway(ctx, *sshListen, serverCfg, store, reg, spool, chatSpool, chatGuard, spoolPump, acmeCtrl, prov, ipv6Prefix, claimLimits, stats, ready.setSSHListening); err != nil {
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
	if strings.TrimSpace(*wellKnownListen) != "" {
		if strings.TrimSpace(*wellKnownFile) == "" {
			log.Fatalf("-well-known-file is required when -well-known-listen is set")
		}
		go func() {
			if err := runWellKnownServer(ctx, *wellKnownListen, *wellKnownPath, *wellKnownFile, time.Duration(*obsReadHeaderTimeoutMS)*time.Millisecond); err != nil {
				log.Printf("well-known server error: %v", err)
				cancel()
			}
		}()
	}

	<-ctx.Done()
}

func runRelayDoctor(dbPath string) int {
	// Keep output intentionally plain: this is for humans and logs.
	fail := 0
	check := func(ok bool, name string, detail string) {
		if ok {
			fmt.Printf("PASS %s\n", name)
			return
		}
		fail = 1
		if strings.TrimSpace(detail) == "" {
			detail = "check failed"
		}
		fmt.Printf("FAIL %s: %s\n", name, detail)
	}

	// Env checks (production-relevant).
	zone := strings.TrimSpace(os.Getenv("SISUMAIL_DNS_ZONE"))
	prefix := strings.TrimSpace(os.Getenv("SISUMAIL_IPV6_PREFIX"))
	pepper := strings.TrimSpace(os.Getenv("SISUMAIL_INVITE_PEPPER"))
	hcloud := strings.TrimSpace(os.Getenv("HCLOUD_TOKEN"))
	if hcloud == "" {
		hcloud = strings.TrimSpace(os.Getenv("HETZNER_CLOUD_TOKEN"))
	}

	check(zone != "", "env:SISUMAIL_DNS_ZONE", "set SISUMAIL_DNS_ZONE (e.g. sisumail.fi)")
	check(prefix != "", "env:SISUMAIL_IPV6_PREFIX", "set SISUMAIL_IPV6_PREFIX (routed /64 for AnyIP Tier1)")
	if zone != "" {
		z := strings.TrimSuffix(zone, ".")
		check(z != "" && strings.Contains(z, "."), "env:SISUMAIL_DNS_ZONE.format", "zone should be a domain name")
	}
	if prefix != "" {
		_, ipnet, err := net.ParseCIDR(prefix)
		ok := err == nil && ipnet != nil
		detail := ""
		if err != nil {
			detail = err.Error()
		}
		check(ok, "env:SISUMAIL_IPV6_PREFIX.parse", detail)
	}
	check(pepper != "", "env:SISUMAIL_INVITE_PEPPER", "set SISUMAIL_INVITE_PEPPER to prevent offline invite guessing")
	check(hcloud != "", "env:HCLOUD_TOKEN", "set HCLOUD_TOKEN so provisioning + acme-dns01 can work")

	// DB checks.
	st, err := identity.Open(dbPath)
	if err != nil {
		check(false, "db:open", err.Error())
		return fail
	}
	defer st.Close()
	if err := st.Init(context.Background()); err != nil {
		check(false, "db:init", err.Error())
		return fail
	}
	check(true, "db:open", "")
	check(true, "db:schema", "")

	// Policy checks.
	check(strings.TrimSpace(os.Getenv("SISUMAIL_ALLOW_CLAIM")) != "true", "policy:allow-claim", "production should keep SISUMAIL_ALLOW_CLAIM=false (invite-only)")

	return fail
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
	if prefixStr == "" {
		return nil, nil
	}
	_, ipnet, err := net.ParseCIDR(prefixStr)
	if err != nil {
		log.Printf("invalid SISUMAIL_IPV6_PREFIX: %v", err)
		return nil, nil
	}
	if token == "" || zone == "" {
		// Allow local/dev runs to allocate from a prefix without DNS automation.
		return nil, ipnet
	}
	dns := hetznercloud.NewClient(token, zone)
	return &provision.Provisioner{DNS: dns, ZoneName: zone}, ipnet
}

func handleClaimV1Channel(ch ssh.NewChannel, identityStatus string, store *identity.Store, reg *relay.SessionRegistry, prov *provision.Provisioner, ipv6Prefix *net.IPNet, claimLimits identity.ClaimLimits, sourceAddr net.Addr, stats *observability.RelayStats) {
	c, reqs, err := ch.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	defer c.Close()

	if identityStatus != "bootstrap" || store == nil || reg == nil {
		_ = proto.WriteClaimResponse(c, proto.ClaimResponse{OK: false, Message: "claim unavailable"})
		return
	}
	devNoProvision := strings.TrimSpace(os.Getenv("SISUMAIL_DEV_CLAIM_NO_PROVISION")) == "1"
	if (prov == nil || ipv6Prefix == nil) && !devNoProvision {
		_ = proto.WriteClaimResponse(c, proto.ClaimResponse{OK: false, Message: "operator not configured"})
		return
	}
	if ipv6Prefix == nil {
		_ = proto.WriteClaimResponse(c, proto.ClaimResponse{OK: false, Message: "operator not configured"})
		return
	}

	req, err := proto.ReadClaimRequest(c)
	if err != nil {
		_ = proto.WriteClaimResponse(c, proto.ClaimResponse{OK: false, Message: "bad request"})
		return
	}

	u, err := identity.CanonicalUsername(req.Username)
	if err != nil || isReservedUsername(u) {
		_ = proto.WriteClaimResponse(c, proto.ClaimResponse{OK: false, Message: "invalid username"})
		return
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PubKeyText))
	if err != nil {
		_ = proto.WriteClaimResponse(c, proto.ClaimResponse{OK: false, Message: "invalid pubkey"})
		return
	}
	bucket := sourceBucket(sourceAddr)
	pepper := strings.TrimSpace(os.Getenv("SISUMAIL_INVITE_PEPPER"))

	id, childInvites, err := store.ClaimWithInvite(context.Background(), u, pub, ipv6Prefix, bucket, claimLimits, req.InviteCode, pepper)
	if err != nil {
		msg := "claim failed"
		switch {
		case errors.Is(err, identity.ErrClaimRateLimited):
			msg = "rate limited"
		case errors.Is(err, identity.ErrInviteInvalid):
			msg = "invite invalid"
		case errors.Is(err, identity.ErrInviteRedeemed):
			msg = "invite redeemed"
		default:
			if strings.Contains(strings.ToLower(err.Error()), "already claimed") {
				msg = "username already claimed"
			}
		}
		_ = proto.WriteClaimResponse(c, proto.ClaimResponse{OK: false, Message: msg})
		return
	}

	// Provision DNS (and any other operator bindings). Roll back on failure.
	if !devNoProvision {
		if err := prov.ProvisionUser(u, id.IPv6); err != nil {
			_ = store.DeleteByUsername(context.Background(), u)
			_ = proto.WriteClaimResponse(c, proto.ClaimResponse{OK: false, Message: "provision failed"})
			return
		}
	}
	reg.SetUserDestIPv6(u, id.IPv6)

	address := fmt.Sprintf("inbox@%s.sisumail.fi", u)
	_ = proto.WriteClaimResponse(c, proto.ClaimResponse{
		OK:       true,
		Username: u,
		IPv6:     id.IPv6.String(),
		Address:  address,
		Invites:  childInvites,
	})
	_ = stats // reserved for future claim counters
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

func runSSHGateway(ctx context.Context, addr string, cfg *ssh.ServerConfig, store *identity.Store, reg *relay.SessionRegistry, spool *tier2.FileSpool, chatSpool *chatqueue.Store, chatGuard *chatGuard, pump *spoolDeliveryPump, acmeCtrl *acmeDNS01Controller, prov *provision.Provisioner, ipv6Prefix *net.IPNet, claimLimits identity.ClaimLimits, stats *observability.RelayStats, onListening func()) error {
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
		go handleSSHConn(ctx, nc, cfg, store, reg, spool, chatSpool, chatGuard, pump, acmeCtrl, prov, ipv6Prefix, claimLimits, stats)
	}
}

func handleSSHConn(ctx context.Context, nc net.Conn, cfg *ssh.ServerConfig, store *identity.Store, reg *relay.SessionRegistry, spool *tier2.FileSpool, chatSpool *chatqueue.Store, chatGuard *chatGuard, pump *spoolDeliveryPump, acmeCtrl *acmeDNS01Controller, prov *provision.Provisioner, ipv6Prefix *net.IPNet, claimLimits identity.ClaimLimits, stats *observability.RelayStats) {
	defer nc.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	defer sshConn.Close()

	rawUser := strings.TrimSpace(sshConn.User())
	if rawUser == "" {
		return
	}
	user := rawUser
	source := remoteIPString(sshConn.RemoteAddr())
	identityStatus := "existing"
	if sshConn.Permissions != nil && sshConn.Permissions.Extensions != nil {
		if s := strings.TrimSpace(sshConn.Permissions.Extensions["identity_status"]); s != "" {
			identityStatus = s
		}
		if cu := strings.TrimSpace(sshConn.Permissions.Extensions["canonical_username"]); cu != "" {
			user = cu
		}
	}
	canon, err := identity.CanonicalUsername(user)
	if err != nil {
		return
	}
	user = canon
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
				channelType := strings.TrimSpace(ch.ChannelType())
				if !isSupportedClientChannelType(channelType) {
					_ = ch.Reject(ssh.UnknownChannelType, "unsupported")
					return
				}
				if identityStatus == "bootstrap" && channelType != "claim-v1" {
					_ = ch.Reject(ssh.Prohibited, "bootstrap session only supports claim-v1")
					return
				}
				switch channelType {
				case "session":
					c, reqs, err := ch.Accept()
					if err != nil {
						return
					}
					mode := pollSessionRequests(reqs, 150*time.Millisecond)
					status := uint32(0)
					if !mode.execLike {
						go func() {
							handleSessionRequests(reqs)
						}()
						status = runHostedShell(c, mode.ptyRequested, hostedShellEnv{
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
				case "claim-v1":
					handleClaimV1Channel(ch, identityStatus, store, reg, prov, ipv6Prefix, claimLimits, sshConn.RemoteAddr(), stats)
				}
			}(newCh)
		}
	}
}

func isSupportedClientChannelType(channelType string) bool {
	switch strings.TrimSpace(channelType) {
	case "session", "key-lookup", "chat-send", "acme-dns01", "claim-v1":
		return true
	default:
		return false
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
	_, err = deliverOrQueueChatCiphertext(sender, h.To, bytes.NewReader(ct), h.SizeBytes, reg, chatSpool, stats)
	if err != nil {
		return
	}
}

func deliverOrQueueChatCiphertext(sender, to string, payload io.Reader, size int64, reg *relay.SessionRegistry, chatSpool *chatqueue.Store, stats *observability.RelayStats) (string, error) {
	if reg == nil || strings.TrimSpace(to) == "" || payload == nil || size < 0 {
		return "", fmt.Errorf("invalid chat delivery args")
	}
	ct, err := io.ReadAll(io.LimitReader(payload, size))
	if err != nil {
		return "", err
	}
	if int64(len(ct)) != size {
		return "", fmt.Errorf("chat payload size mismatch")
	}

	queue := func() (string, error) {
		if chatSpool == nil {
			return "dropped", nil
		}
		id := fmt.Sprintf("%d", time.Now().UnixNano())
		meta := chatqueue.Meta{
			ID:         id,
			From:       sender,
			To:         to,
			ReceivedAt: time.Now(),
		}
		if err := chatSpool.Put(to, id, bytes.NewReader(ct), meta); err != nil {
			return "", err
		}
		if stats != nil {
			stats.IncChatQueuedOffline()
		}
		return "queued-encrypted", nil
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
	return "delivered-live", nil
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

type sessionMode struct {
	execLike     bool
	ptyRequested bool
}

func pollSessionRequests(reqs <-chan *ssh.Request, wait time.Duration) (mode sessionMode) {
	if wait <= 0 {
		wait = 150 * time.Millisecond
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()

	// First request: wait briefly for common ssh request patterns (exec/shell/pty).
	select {
	case req, ok := <-reqs:
		if ok {
			execLike, ptyRequested := handleSessionRequest(req)
			mode.execLike = mode.execLike || execLike
			mode.ptyRequested = mode.ptyRequested || ptyRequested
		}
	case <-timer.C:
	}

	// Drain any requests that are already queued without blocking.
	for {
		select {
		case req, ok := <-reqs:
			if !ok {
				return mode
			}
			execLike, ptyRequested := handleSessionRequest(req)
			mode.execLike = mode.execLike || execLike
			mode.ptyRequested = mode.ptyRequested || ptyRequested
		default:
			return mode
		}
	}
}

func handleSessionRequest(req *ssh.Request) (execLike bool, ptyRequested bool) {
	if req == nil {
		return false, false
	}
	reqType := strings.TrimSpace(strings.ToLower(req.Type))
	allow, isExecLike := sessionRequestAllowed(reqType)
	if req.WantReply {
		_ = req.Reply(allow, nil)
	}
	return isExecLike, reqType == "pty-req"
}

func handleSessionRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		_, _ = handleSessionRequest(req)
	}
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

type shellSettings struct {
	compact bool
	motd    bool
}

type shellEditorState struct {
	history   []string
	histIndex int
	draft     string
}

type shellSessionState struct {
	settings shellSettings
	editor   shellEditorState
}

func runHostedShell(ch ssh.Channel, ptyRequested bool, env hostedShellEnv) uint32 {
	if ch == nil {
		return 1
	}
	in := bufio.NewReader(ch)
	state := shellSessionState{
		settings: shellSettings{compact: false, motd: true},
		editor:   shellEditorState{histIndex: -1},
	}
	if state.settings.motd {
		shellWrite(ch, "Sisumail Hosted Shell\n")
		if env.identityStatus == "claimed-new" {
			shellWrite(ch, "identity claimed and bound to your SSH key\n")
		}
		shellWrite(ch, "Sisumail is sovereign receive-only mail infrastructure.\n")
		shellWrite(ch, "It is not an outbound email sending platform.\n")
		shellWrite(ch, "Encrypted chat is optional and meant for coordination.\n")
		shellWrite(ch, "Type help (or /help). Quick chat note: <user> <message>\n")
	}
	for {
		prompt := env.promptString(state.settings.compact)
		shellWrite(ch, prompt)
		line, err := shellReadLine(in, ch, ptyRequested, prompt, &state.editor, env.completeToken)
		if err != nil {
			if err == io.EOF {
				return 0
			}
			return 1
		}
		rememberHistory(&state.editor, line)
		kind, a, b := parseRelayShellDirective(line)
		switch kind {
		case "noop":
			continue
		case "quit":
			return 0
		case "help":
			writeShellHelp(ch, a)
		case "examples":
			shellWrite(ch, "Examples:\n")
			shellWrite(ch, "lookup niklas\n")
			shellWrite(ch, "niklas hello from hosted shell\n")
			shellWrite(ch, "status\n")
			shellWrite(ch, "chatq\n")
			shellWrite(ch, "set compact on\n")
		case "clear":
			if ptyRequested {
				_, _ = io.WriteString(ch, "\x1b[2J\x1b[H")
			} else {
				shellWrite(ch, "\n\n\n")
			}
		case "set":
			key, val, ok := parseSetCommand(a)
			if !ok {
				shellWrite(ch, "usage: set compact on|off\n")
				continue
			}
			if key == "compact" {
				state.settings.compact = val == "on"
				shellPrintf(ch, "compact=%s\n", val)
				continue
			}
			shellWrite(ch, "usage: set compact on|off\n")
		case "motd":
			val, ok := parseOnOff(a)
			if !ok {
				shellWrite(ch, "usage: motd on|off\n")
				continue
			}
			state.settings.motd = val == "on"
			shellPrintf(ch, "motd=%s (session scope)\n", val)
		case "whoami":
			shellPrintf(ch, "user=%s source=%s\n", env.username, env.source)
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
			shellPrintf(ch, "chat_queue=%d mail_queue=%d\n", chatQueued, mailQueued)
		case "lookup":
			target := strings.TrimSpace(a)
			if target == "" {
				shellWrite(ch, "usage: ¤lookup <user>\n")
				continue
			}
			id, err := env.lookup(target)
			if err != nil {
				shellPrintf(ch, "lookup failed: %v\n", err)
				continue
			}
			if id == nil {
				shellWrite(ch, "not found\n")
				continue
			}
			online := false
			if env.reg != nil {
				_, online = env.reg.GetSession(target)
			}
			shellPrintf(ch, "user=%s fp=%s online=%v\n", id.Username, id.Fingerprint, online)
		case "chatq":
			qcmd, err := parseChatQCommand(a)
			if err != nil {
				shellPrintf(ch, "chatq: %v\n", err)
				shellWrite(ch, "usage: chatq [--full] [--from <user>] [--since <duration>] | chatq read <id> | chatq ack <id>\n")
				continue
			}
			if env.chatSpool == nil {
				shellWrite(ch, "chat queue unavailable\n")
				continue
			}
			switch qcmd.mode {
			case "read":
				_, meta, err := env.chatSpool.Get(env.username, qcmd.id)
				if err != nil {
					if os.IsNotExist(err) {
						shellWrite(ch, "chatq read: not found\n")
					} else {
						shellPrintf(ch, "chatq read failed: %v\n", err)
					}
					continue
				}
				shellWrite(ch, "chat message is end-to-end encrypted; relay cannot decrypt content.\n")
				shellPrintf(ch, "id=%s from=%s bytes=%d at=%s age=%s\n", meta.ID, meta.From, meta.SizeBytes, meta.ReceivedAt.UTC().Format(time.RFC3339), formatRelativeTime(meta.ReceivedAt.UTC(), time.Now().UTC()))
			case "ack":
				if err := env.chatSpool.Ack(env.username, qcmd.id); err != nil {
					shellPrintf(ch, "chatq ack failed: %v\n", err)
					continue
				}
				if env.stats != nil {
					env.stats.IncChatAcked()
				}
				shellPrintf(ch, "acked %s\n", qcmd.id)
			default:
				list, err := env.chatSpool.List(env.username)
				if err != nil {
					shellPrintf(ch, "chatq failed: %v\n", err)
					continue
				}
				filtered := filterChatQueue(list, qcmd, time.Now().UTC())
				shellPrintf(ch, "queued chat messages: %d\n", len(filtered))
				now := time.Now().UTC()
				for i := 0; i < len(filtered) && i < 10; i++ {
					m := filtered[i]
					if qcmd.fullTimestamps {
						shellPrintf(ch, "%s from=%s bytes=%d at=%s\n", m.ID, m.From, m.SizeBytes, m.ReceivedAt.UTC().Format(time.RFC3339))
						continue
					}
					shellPrintf(ch, "%s from=%s bytes=%d age=%s\n", m.ID, m.From, m.SizeBytes, formatRelativeTime(m.ReceivedAt.UTC(), now))
				}
			}
		case "mailq":
			if env.spool == nil {
				shellWrite(ch, "mail queue unavailable\n")
				continue
			}
			list, err := env.spool.List(env.username)
			if err != nil {
				shellPrintf(ch, "mailq failed: %v\n", err)
				continue
			}
			shellPrintf(ch, "queued encrypted mail items: %d\n", len(list))
			shellWrite(ch, "mail bodies stay encrypted; use local sisumail client to decrypt/read.\n")
		case "send":
			to := strings.TrimSpace(a)
			msg := strings.TrimSpace(b)
			if to == "" || msg == "" {
				shellWrite(ch, "usage: ¤<user> <message>\n")
				continue
			}
			mode, err := env.sendHostedChat(to, msg)
			if err != nil {
				shellPrintf(ch, "send failed: %v\n", err)
				continue
			}
			renderSendResult(ch, mode)
		case "reply":
			id := strings.TrimSpace(a)
			msg := strings.TrimSpace(b)
			if id == "" || msg == "" {
				shellWrite(ch, "usage: reply <id> <message>\n")
				continue
			}
			if env.chatSpool == nil {
				shellWrite(ch, "chat queue unavailable\n")
				continue
			}
			rc, meta, err := env.chatSpool.Get(env.username, id)
			if err != nil {
				if os.IsNotExist(err) {
					shellWrite(ch, "reply: id not found\n")
				} else {
					shellPrintf(ch, "reply failed: %v\n", err)
				}
				continue
			}
			_ = rc.Close()
			if strings.TrimSpace(meta.From) == "" {
				shellWrite(ch, "reply failed: sender missing\n")
				continue
			}
			mode, err := env.sendHostedChat(meta.From, msg)
			if err != nil {
				shellPrintf(ch, "reply failed: %v\n", err)
				continue
			}
			renderSendResult(ch, mode)
		case "unknown":
			bad := strings.TrimSpace(a)
			if suggestion := suggestShellCommand(bad); suggestion != "" {
				shellPrintf(ch, "unknown command: %s (did you mean %s?)\n", bad, suggestion)
			} else {
				shellPrintf(ch, "unknown command: %s\n", bad)
			}
			shellWrite(ch, "Type help (or /help).\n")
		default:
			shellWrite(ch, "unknown command. Type help (or /help).\n")
		}
	}
}

func renderSendResult(ch ssh.Channel, mode string) {
	switch strings.TrimSpace(strings.ToLower(mode)) {
	case "delivered-live":
		shellWrite(ch, "delivery=delivered-live\n")
	case "queued-encrypted", "queued":
		shellWrite(ch, "delivery=queued (recipient can decrypt in local/node mode)\n")
	default:
		shellPrintf(ch, "delivery=%s\n", strings.TrimSpace(mode))
	}
}

func shellReadLine(in *bufio.Reader, ch ssh.Channel, ptyRequested bool, prompt string, editor *shellEditorState, complete func(string) []string) (string, error) {
	if in == nil {
		return "", io.EOF
	}
	if !ptyRequested {
		return in.ReadString('\n')
	}
	buf := make([]byte, 0, 128)
	for {
		b, err := in.ReadByte()
		if err != nil {
			if err == io.EOF && len(buf) > 0 {
				shellWrite(ch, "\n")
				return string(buf), nil
			}
			return "", err
		}
		switch b {
		case '\r', '\n':
			shellWrite(ch, "\n")
			if editor != nil {
				editor.histIndex = -1
				editor.draft = ""
			}
			return string(buf), nil
		case 0x7f, 0x08:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				_, _ = io.WriteString(ch, "\b \b")
			}
		case '\t':
			start, prefix := completionToken(buf)
			var candidates []string
			if complete != nil {
				candidates = complete(prefix)
			}
			switch len(candidates) {
			case 0:
				_, _ = io.WriteString(ch, "\a")
			case 1:
				replacement := []byte(candidates[0] + " ")
				buf = append(append([]byte{}, buf[:start]...), replacement...)
				redrawInputLine(ch, prompt, buf)
			default:
				shellWrite(ch, "\n")
				shellWrite(ch, strings.Join(candidates, " ")+"\n")
				redrawInputLine(ch, prompt, buf)
			}
		case 0x1b:
			// Basic ANSI arrows for history navigation.
			next, err := in.ReadByte()
			if err != nil {
				return "", err
			}
			if next != '[' {
				continue
			}
			key, err := in.ReadByte()
			if err != nil {
				return "", err
			}
			if editor == nil {
				continue
			}
			switch key {
			case 'A': // up
				if len(editor.history) == 0 {
					continue
				}
				if editor.histIndex == -1 {
					editor.draft = string(buf)
					editor.histIndex = len(editor.history) - 1
				} else if editor.histIndex > 0 {
					editor.histIndex--
				}
				buf = []byte(editor.history[editor.histIndex])
				redrawInputLine(ch, prompt, buf)
			case 'B': // down
				if editor.histIndex == -1 {
					continue
				}
				if editor.histIndex < len(editor.history)-1 {
					editor.histIndex++
					buf = []byte(editor.history[editor.histIndex])
				} else {
					editor.histIndex = -1
					buf = []byte(editor.draft)
				}
				redrawInputLine(ch, prompt, buf)
			}
		case 0x03:
			buf = buf[:0]
			shellWrite(ch, "^C\n")
			return "", nil
		default:
			// In PTY mode the client expects remote-side echo.
			if b >= 32 || b == '\t' {
				buf = append(buf, b)
				_, _ = ch.Write([]byte{b})
			}
		}
	}
}

func redrawInputLine(ch ssh.Channel, prompt string, buf []byte) {
	if ch == nil {
		return
	}
	_, _ = io.WriteString(ch, "\r")
	_, _ = io.WriteString(ch, prompt)
	_, _ = ch.Write(buf)
	_, _ = io.WriteString(ch, "\x1b[K")
}

func completionToken(buf []byte) (start int, prefix string) {
	start = len(buf)
	for start > 0 {
		if buf[start-1] == ' ' || buf[start-1] == '\t' {
			break
		}
		start--
	}
	return start, strings.ToLower(string(buf[start:]))
}

func shellWrite(ch ssh.Channel, s string) {
	if ch == nil || s == "" {
		return
	}
	// SSH channels are byte streams, not terminal devices; normalize to CRLF
	// for predictable cursor positioning in interactive clients.
	normalized := strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
	_, _ = io.WriteString(ch, normalized)
}

func shellPrintf(ch ssh.Channel, format string, args ...any) {
	shellWrite(ch, fmt.Sprintf(format, args...))
}

func rememberHistory(editor *shellEditorState, line string) {
	if editor == nil {
		return
	}
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return
	}
	if len(editor.history) > 0 && editor.history[len(editor.history)-1] == trimmed {
		return
	}
	editor.history = append(editor.history, trimmed)
	if len(editor.history) > 100 {
		editor.history = editor.history[len(editor.history)-100:]
	}
	editor.histIndex = -1
	editor.draft = ""
}

func (env hostedShellEnv) queueCounts() (chatQueued int, mailQueued int) {
	if env.chatSpool != nil {
		if list, err := env.chatSpool.List(env.username); err == nil {
			chatQueued = len(list)
		}
	}
	if env.spool != nil {
		if list, err := env.spool.List(env.username); err == nil {
			mailQueued = len(list)
		}
	}
	return chatQueued, mailQueued
}

func (env hostedShellEnv) promptString(compact bool) string {
	chatQueued, mailQueued := env.queueCounts()
	if compact {
		return fmt.Sprintf("sisu:%s> ", env.username)
	}
	return fmt.Sprintf("sisu:%s [c:%d m:%d]> ", env.username, chatQueued, mailQueued)
}

func (env hostedShellEnv) completeToken(prefix string) []string {
	p := strings.TrimSpace(strings.ToLower(prefix))
	set := map[string]struct{}{}
	add := func(s string) {
		if strings.HasPrefix(strings.ToLower(s), p) {
			set[s] = struct{}{}
		}
	}
	for _, c := range shellCompletionWords {
		add(c)
	}
	if strings.HasPrefix("--full", p) {
		set["--full"] = struct{}{}
	}
	if env.store != nil {
		ids, err := env.store.All(context.Background())
		if err == nil {
			for _, id := range ids {
				add(id.Username)
			}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func writeShellHelp(ch ssh.Channel, topic string) {
	switch strings.ToLower(strings.TrimSpace(topic)) {
	case "", "all":
		shellWrite(ch, "Commands:\n")
		shellWrite(ch, "help [command]\nexamples\nwhoami\nstatus\nlookup <user>\nchatq [--full] [--from <user>] [--since <duration>]\nchatq read <id>\nchatq ack <id>\nreply <id> <message>\nmailq\nclear\nset compact on|off\nmotd on|off\nquit\n")
		shellWrite(ch, "Aliases: ? h (help), stat (status), ls (chatq), q/exit (quit).\n")
		shellWrite(ch, "You can prefix commands with / or ¤.\n")
		shellWrite(ch, "Quick chat note: <user> <message>\n")
		shellWrite(ch, "Sisumail receives mail; outbound internet email sending is out of scope.\n")
	case "chatq", "ls":
		shellWrite(ch, "chatq [--full] [--from <user>] [--since <duration>]\n")
		shellWrite(ch, "Shows up to 10 queued encrypted chat items.\n")
		shellWrite(ch, "Default output shows relative age; use --full for RFC3339 timestamps.\n")
		shellWrite(ch, "Subcommands: chatq read <id>, chatq ack <id>\n")
	case "reply", "r":
		shellWrite(ch, "reply <id> <message>\n")
		shellWrite(ch, "Replies to the sender of a queued chat entry.\n")
	case "lookup", "l":
		shellWrite(ch, "lookup <user>\n")
		shellWrite(ch, "Shows fingerprint and online status for a user.\n")
	case "status", "s", "stat":
		shellWrite(ch, "status\n")
		shellWrite(ch, "Shows your chat and mail queue counts.\n")
	case "whoami", "me":
		shellWrite(ch, "whoami\n")
		shellWrite(ch, "Shows authenticated user and source IP.\n")
	case "mailq":
		shellWrite(ch, "mailq\n")
		shellWrite(ch, "Shows queued encrypted mail item count.\n")
	case "clear", "cls":
		shellWrite(ch, "clear\n")
		shellWrite(ch, "Clears terminal screen in interactive sessions.\n")
	case "set":
		shellWrite(ch, "set compact on|off\n")
		shellWrite(ch, "Toggles compact prompt mode for this session.\n")
	case "motd":
		shellWrite(ch, "motd on|off\n")
		shellWrite(ch, "Toggles session message-of-the-day output setting.\n")
	case "examples", "x":
		shellWrite(ch, "examples\n")
		shellWrite(ch, "Shows common command examples.\n")
	case "quit", "q", "exit":
		shellWrite(ch, "quit\n")
		shellWrite(ch, "Ends the hosted shell session.\n")
	default:
		if suggestion := suggestShellCommand(topic); suggestion != "" {
			shellPrintf(ch, "unknown help topic: %s (did you mean %s?)\n", strings.TrimSpace(topic), suggestion)
		} else {
			shellPrintf(ch, "unknown help topic: %s\n", strings.TrimSpace(topic))
		}
	}
}

func parseSetCommand(raw string) (key string, val string, ok bool) {
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(raw)))
	if len(fields) != 2 {
		return "", "", false
	}
	if fields[0] != "compact" {
		return "", "", false
	}
	onOff, ok := parseOnOff(fields[1])
	if !ok {
		return "", "", false
	}
	return fields[0], onOff, true
}

type chatQCommand struct {
	mode           string
	id             string
	fromUser       string
	since          time.Duration
	fullTimestamps bool
}

func parseChatQCommand(raw string) (chatQCommand, error) {
	cmd := chatQCommand{mode: "list"}
	parts := strings.Fields(strings.TrimSpace(raw))
	if len(parts) == 0 {
		return cmd, nil
	}
	switch strings.ToLower(parts[0]) {
	case "read":
		if len(parts) != 2 {
			return cmd, fmt.Errorf("usage: chatq read <id>")
		}
		cmd.mode = "read"
		cmd.id = strings.TrimSpace(parts[1])
		if cmd.id == "" {
			return cmd, fmt.Errorf("empty id")
		}
		return cmd, nil
	case "ack":
		if len(parts) != 2 {
			return cmd, fmt.Errorf("usage: chatq ack <id>")
		}
		cmd.mode = "ack"
		cmd.id = strings.TrimSpace(parts[1])
		if cmd.id == "" {
			return cmd, fmt.Errorf("empty id")
		}
		return cmd, nil
	}
	for i := 0; i < len(parts); i++ {
		switch parts[i] {
		case "--full":
			cmd.fullTimestamps = true
		case "--from":
			if i+1 >= len(parts) {
				return cmd, fmt.Errorf("missing value for --from")
			}
			i++
			cmd.fromUser = strings.ToLower(strings.TrimSpace(parts[i]))
			if cmd.fromUser == "" {
				return cmd, fmt.Errorf("empty --from value")
			}
		case "--since":
			if i+1 >= len(parts) {
				return cmd, fmt.Errorf("missing value for --since")
			}
			i++
			d, err := parseSinceDuration(parts[i])
			if err != nil {
				return cmd, fmt.Errorf("bad --since: %v", err)
			}
			cmd.since = d
		default:
			return cmd, fmt.Errorf("unknown option %q", parts[i])
		}
	}
	return cmd, nil
}

func parseSinceDuration(s string) (time.Duration, error) {
	raw := strings.ToLower(strings.TrimSpace(s))
	if raw == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if strings.HasSuffix(raw, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(raw, "d"))
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid day duration")
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, err
	}
	if d < 0 {
		return 0, fmt.Errorf("duration must be >= 0")
	}
	return d, nil
}

func filterChatQueue(list []chatqueue.Meta, cmd chatQCommand, now time.Time) []chatqueue.Meta {
	if len(list) == 0 {
		return nil
	}
	out := make([]chatqueue.Meta, 0, len(list))
	for _, m := range list {
		if cmd.fromUser != "" && !strings.EqualFold(strings.TrimSpace(m.From), cmd.fromUser) {
			continue
		}
		if cmd.since > 0 && now.Sub(m.ReceivedAt.UTC()) > cmd.since {
			continue
		}
		out = append(out, m)
	}
	return out
}

func parseOnOff(raw string) (string, bool) {
	v := strings.ToLower(strings.TrimSpace(raw))
	switch v {
	case "on":
		return "on", true
	case "off":
		return "off", true
	default:
		return "", false
	}
}

func formatRelativeTime(t, now time.Time) string {
	d := now.Sub(t)
	future := d < 0
	if future {
		d = -d
	}
	var unit string
	var n int64
	switch {
	case d < 10*time.Second:
		if future {
			return "in a moment"
		}
		return "just now"
	case d < time.Minute:
		unit = "s"
		n = int64(d / time.Second)
	case d < time.Hour:
		unit = "m"
		n = int64(d / time.Minute)
	case d < 24*time.Hour:
		unit = "h"
		n = int64(d / time.Hour)
	default:
		unit = "d"
		n = int64(d / (24 * time.Hour))
	}
	if future {
		return fmt.Sprintf("in %d%s", n, unit)
	}
	return fmt.Sprintf("%d%s ago", n, unit)
}

var shellCommandWords = []string{
	"help", "examples", "whoami", "status", "lookup", "chatq", "reply", "mailq", "clear", "set", "motd", "quit",
}

var shellCompletionWords = []string{
	"help", "examples", "whoami", "status", "stat", "lookup", "chatq", "read", "ack", "reply", "r", "mailq", "ls", "clear", "set", "motd", "quit", "exit", "?", "h", "--full", "--from", "--since",
}

func suggestShellCommand(in string) string {
	word := strings.ToLower(strings.TrimSpace(in))
	if word == "" {
		return ""
	}
	best := ""
	bestDist := 99
	for _, candidate := range shellCommandWords {
		if strings.HasPrefix(candidate, word) || strings.HasPrefix(word, candidate) {
			if len(word) > 1 {
				return candidate
			}
		}
		d := levenshteinDistance(word, candidate)
		if d < bestDist {
			best = candidate
			bestDist = d
		}
	}
	if bestDist <= 2 {
		return best
	}
	return ""
}

func levenshteinDistance(a, b string) int {
	if a == b {
		return 0
	}
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := 0; j <= len(b); j++ {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			ins := curr[j-1] + 1
			del := prev[j] + 1
			sub := prev[j-1] + cost
			curr[j] = minInt(ins, del, sub)
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

func minInt(v int, rest ...int) int {
	m := v
	for _, n := range rest {
		if n < m {
			m = n
		}
	}
	return m
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

func (env hostedShellEnv) sendHostedChat(to, message string) (string, error) {
	target, err := env.lookup(to)
	if err != nil {
		return "", err
	}
	if target == nil {
		return "", fmt.Errorf("unknown user")
	}
	if env.guard != nil && (!env.guard.allowSendBySource(env.source) || !env.guard.allowSendByUser(env.username)) {
		if env.stats != nil {
			env.stats.IncChatSendLimited()
		}
		return "", fmt.Errorf("rate limited")
	}
	if env.stats != nil {
		env.stats.IncChatSendTotal()
	}
	var ct bytes.Buffer
	if err := tier2.StreamEncrypt(&ct, strings.NewReader(message), target.PubKeyText); err != nil {
		return "", err
	}
	size := int64(ct.Len())
	if env.guard != nil && env.guard.maxBytes > 0 && size > env.guard.maxBytes {
		return "", fmt.Errorf("message too large")
	}
	return deliverOrQueueChatCiphertext(env.username, target.Username, bytes.NewReader(ct.Bytes()), size, env.reg, env.chatSpool, env.stats)
}

func parseRelayShellDirective(line string) (kind string, arg1 string, arg2 string) {
	s := strings.TrimSpace(line)
	if s == "" {
		return "noop", "", ""
	}
	prefix := ""
	if strings.HasPrefix(s, "¤") {
		prefix = "¤"
		s = strings.TrimSpace(strings.TrimPrefix(s, "¤"))
	} else if strings.HasPrefix(s, "/") {
		prefix = "/"
		s = strings.TrimSpace(strings.TrimPrefix(s, "/"))
	}
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
	case "?", "help", "h":
		return "help", strings.TrimSpace(strings.TrimPrefix(s, parts[0])), ""
	case "examples", "x":
		return "examples", "", ""
	case "whoami", "me":
		return "whoami", "", ""
	case "status", "s", "stat":
		return "status", "", ""
	case "lookup", "l":
		if len(parts) < 2 {
			return "lookup", "", ""
		}
		return "lookup", parts[1], ""
	case "chatq", "ls":
		return "chatq", strings.TrimSpace(strings.TrimPrefix(s, parts[0])), ""
	case "reply", "r":
		if len(parts) < 3 {
			return "reply", "", ""
		}
		return "reply", parts[1], strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(s, parts[0])), parts[1]))
	case "mailq":
		return "mailq", "", ""
	case "clear", "cls":
		return "clear", "", ""
	case "set":
		return "set", strings.TrimSpace(strings.TrimPrefix(s, parts[0])), ""
	case "motd":
		return "motd", strings.TrimSpace(strings.TrimPrefix(s, parts[0])), ""
	default:
		if len(parts) < 2 || prefix == "/" {
			return "unknown", cmd, ""
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

func sourceBucket(addr net.Addr) string {
	host := remoteIPString(addr)
	ip := net.ParseIP(host)
	if ip == nil {
		return "unknown"
	}
	if ip4 := ip.To4(); ip4 != nil {
		m := net.CIDRMask(24, 32)
		netIP := ip4.Mask(m)
		return "v4:" + (&net.IPNet{IP: netIP, Mask: m}).String()
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return "unknown"
	}
	m := net.CIDRMask(64, 128)
	netIP := ip16.Mask(m)
	return "v6:" + (&net.IPNet{IP: netIP, Mask: m}).String()
}

func isLookupUsernameAllowed(u string) bool {
	u, err := identity.CanonicalUsername(u)
	if err != nil {
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
