package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/sisumail/sisumail/internal/core"
	"github.com/sisumail/sisumail/internal/dns/hetznercloud"
	"github.com/sisumail/sisumail/internal/proto"
	"github.com/sisumail/sisumail/internal/store/chatlog"
	"github.com/sisumail/sisumail/internal/store/knownkeys"
	"github.com/sisumail/sisumail/internal/store/maildir"
	"github.com/sisumail/sisumail/internal/tier2"
	"github.com/sisumail/sisumail/internal/tlsboot"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const localSMTPMaxMessageBytes = 5 << 20 // 5 MiB cap to bound MIME/attachment abuse.

func runClientDoctor(keyPath, knownHostsPath, configPath string) int {
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

	// Key file.
	if strings.TrimSpace(keyPath) == "" {
		check(false, "key:path", "missing -key (or config override)")
	} else {
		b, err := os.ReadFile(keyPath)
		if err != nil {
			check(false, "key:read", err.Error())
		} else if _, err := ssh.ParsePrivateKey(b); err != nil {
			check(false, "key:parse", err.Error())
		} else {
			check(true, "key:parse", "")
		}
	}

	// known_hosts file.
	if strings.TrimSpace(knownHostsPath) == "" {
		check(false, "known_hosts:path", "missing -known-hosts (or config override)")
	} else if _, err := os.Stat(knownHostsPath); err != nil {
		check(false, "known_hosts:stat", err.Error())
	} else {
		check(true, "known_hosts:stat", "")
	}

	// Config file path (we don't require it to exist because users can run flag-only,
	// but it helps detect surprising locations/permissions).
	if strings.TrimSpace(configPath) == "" {
		check(false, "config:path", "missing -config")
	} else if _, err := os.Stat(configPath); err != nil {
		check(false, "config:stat", err.Error())
	} else {
		check(true, "config:stat", "")
	}

	// TLS store sanity: catch corrupted cert files that cause confusing bootstrap loops.
	home := os.Getenv("HOME")
	if home != "" {
		dir := filepath.Join(home, ".local", "share", "sisumail", "tls")
		if entries, err := os.ReadDir(dir); err == nil {
			var anyBad bool
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				name := e.Name()
				if !strings.HasSuffix(name, ".crt.pem") {
					continue
				}
				p := filepath.Join(dir, name)
				b, err := os.ReadFile(p)
				if err != nil {
					anyBad = true
					continue
				}
				blk, _ := pem.Decode(b)
				if blk == nil || blk.Type != "CERTIFICATE" {
					anyBad = true
					continue
				}
				if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
					anyBad = true
				}
			}
			check(!anyBad, "tls:cert-parse", "one or more certs in ~/.local/share/sisumail/tls failed to parse")
		}
	}

	return fail
}

func runClientDoctorFull(keyPath, knownHostsPath, configPath, relayAddr string, insecureHostKey bool, full bool) int {
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

	// Reuse the existing local checks first (prints PASS/FAIL already).
	if code := runClientDoctor(keyPath, knownHostsPath, configPath); code != 0 {
		fail = 1
	}

	if !full {
		return fail
	}

	// Relay reachability check (TCP dial).
	if strings.TrimSpace(relayAddr) == "" {
		check(false, "relay:addr", "missing -relay")
		return fail
	}
	d := net.Dialer{Timeout: 4 * time.Second}
	c, err := d.Dial("tcp", relayAddr)
	if err != nil {
		check(false, "relay:tcp", err.Error())
	} else {
		_ = c.Close()
		check(true, "relay:tcp", "")
	}

	// Host key pinning stance.
	if insecureHostKey {
		check(false, "relay:hostkey", "-insecure-host-key is enabled (disable for production)")
	} else {
		// Try to construct known_hosts callback; this fails if file is missing/corrupt.
		_, err := buildHostKeyCallback(false, knownHostsPath)
		check(err == nil, "relay:hostkey", "known_hosts callback failed: "+errString(err))
	}

	return fail
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func main() {
	home := os.Getenv("HOME")
	argProfile, argProfileSet := detectProfileFromArgs(os.Args[1:])
	preProfile := "default"
	if argProfileSet {
		preProfile = argProfile
	}
	def := defaultsForProfile(home, preProfile)

	var (
		profile             = flag.String("profile", preProfile, "identity profile name (default: default)")
		configPath          = flag.String("config", def.ConfigPath, "config file path for default flags")
		initConfig          = flag.Bool("init", false, "write current core settings to -config and exit")
		relayAddr           = flag.String("relay", "sisumail.fi:2222", "relay SSH address (default sisumail.fi:2222)")
		user                = flag.String("user", "niklas", "sisumail username")
		zone                = flag.String("zone", "sisumail.fi", "root zone name")
		keyPath             = flag.String("key", def.KeyPath, "ssh private key path")
		knownHostsPath      = flag.String("known-hosts", filepath.Join(home, ".ssh", "known_hosts"), "known_hosts file for relay host key verification")
		insecureHostKey     = flag.Bool("insecure-host-key", false, "disable relay host key verification (development/testing only)")
		smtpListen          = flag.String("smtp-listen", "127.0.0.1:2526", "local SMTP daemon listen address")
		tlsPolicy           = flag.String("tls-policy", "strict", "tls bootstrap policy: pragmatic|strict")
		certPath            = flag.String("tls-cert", "", "path to TLS cert PEM (optional; ACME will populate later)")
		keyPemPath          = flag.String("tls-key", "", "path to TLS key PEM (optional; ACME will populate later)")
		acmeDNS01Enabled    = flag.Bool("acme-dns01", true, "enable ACME DNS-01 certificate automation")
		acmeViaRelay        = flag.Bool("acme-via-relay", true, "use relay ACME DNS-01 control channel instead of direct DNS API token")
		acmeDirectoryURL    = flag.String("acme-directory-url", "", "ACME directory URL (default: Let's Encrypt production)")
		acmeEmail           = flag.String("acme-email", "", "optional ACME account email")
		acmeAccountKeyPath  = flag.String("acme-account-key", "", "path to ACME account key PEM")
		acmeRenewBefore     = flag.Duration("acme-renew-before", 30*24*time.Hour, "renew cert when expiry is within this duration")
		acmeCheckInterval   = flag.Duration("acme-check-interval", 6*time.Hour, "periodic ACME renewal check interval")
		acmePropagationWait = flag.Duration("acme-propagation-wait", 20*time.Second, "wait after DNS-01 TXT upsert before validation")
		acmeIssueTimeout    = flag.Duration("acme-issue-timeout", 4*time.Minute, "timeout for a single ACME issue/renew attempt")
		maildirRoot         = flag.String("maildir", def.MaildirRoot, "local Maildir root")
		inboxMode           = flag.Bool("inbox", false, "list local inbox and exit")
		readID              = flag.String("read-id", "", "read local message by ID and exit")
		tuiMode             = flag.Bool("tui", false, "interactive local inbox view")
		shellMode           = flag.Bool("shell", false, "minimal command shell (prefix commands with ¤)")
		chatTo              = flag.String("chat-to", "", "send encrypted chat message to username (relay session must be online)")
		chatMsg             = flag.String("chat-msg", "", "chat message text (required with -chat-to)")
		chatWith            = flag.String("chat-with", "", "interactive chat session with username")
		chatDir             = flag.String("chat-dir", def.ChatDir, "local chat history directory")
		chatContactsPath    = flag.String("chat-contacts-path", def.ChatContactsPath, "chat contact allowlist file path")
		knownKeysPath       = flag.String("known-keys", def.KnownKeysPath, "pinned peer key fingerprints")
		chatHistory         = flag.String("chat-history", "", "print chat history with username and exit")
		chatLimit           = flag.Int("chat-limit", 100, "max chat history lines for -chat-history (0 = unlimited)")
		chatAllow           = flag.String("chat-allow", "", "add chat contact to allowlist and exit")
		chatDisallow        = flag.String("chat-disallow", "", "remove chat contact from allowlist and exit")
		chatContactsList    = flag.Bool("chat-contacts", false, "print allowed chat contacts and exit")
		aliasPolicyPath     = flag.String("alias-policy-path", def.AliasPolicyPath, "alias policy file path (blocked aliases)")
		apiListen           = flag.String("api-listen", "127.0.0.1:3490", "local HTTP app/API listen address (default 127.0.0.1:3490)")
		apiTokenPath        = flag.String("api-token-path", def.APITokenPath, "local API bearer token file path")
		activeProfilePath   = flag.String("active-profile-path", def.ActiveProfilePath, "path for remembered active profile")
		claimUsername       = flag.String("claim", "", "invite-only: claim a new sisumail username (uses your -key) and exit")
		claimInviteCode     = flag.String("claim-invite", "", "invite-only: invite code for -claim")
		doctor              = flag.Bool("doctor", false, "print local readiness checks and exit")
		doctorFull          = flag.Bool("doctor-full", false, "run extended checks (relay reachability, host key pinning) and exit")
	)
	flag.Parse()
	*profile = normalizeProfileName(*profile)
	explicit := visitedFlags()
	if err := applyConfigOverrides(*configPath, explicit, map[string]configField{
		"profile":             {FlagName: "profile", Set: setString(profile)},
		"relay":               {FlagName: "relay", Set: setString(relayAddr)},
		"user":                {FlagName: "user", Set: setString(user)},
		"zone":                {FlagName: "zone", Set: setString(zone)},
		"key":                 {FlagName: "key", Set: setString(keyPath)},
		"known-hosts":         {FlagName: "known-hosts", Set: setString(knownHostsPath)},
		"insecure-host-key":   {FlagName: "insecure-host-key", Set: setBool(insecureHostKey)},
		"smtp-listen":         {FlagName: "smtp-listen", Set: setString(smtpListen)},
		"tls-policy":          {FlagName: "tls-policy", Set: setString(tlsPolicy)},
		"acme-dns01":          {FlagName: "acme-dns01", Set: setBool(acmeDNS01Enabled)},
		"acme-via-relay":      {FlagName: "acme-via-relay", Set: setBool(acmeViaRelay)},
		"shell":               {FlagName: "shell", Set: setBool(shellMode)},
		"maildir":             {FlagName: "maildir", Set: setString(maildirRoot)},
		"chat-dir":            {FlagName: "chat-dir", Set: setString(chatDir)},
		"chat-contacts-path":  {FlagName: "chat-contacts-path", Set: setString(chatContactsPath)},
		"known-keys":          {FlagName: "known-keys", Set: setString(knownKeysPath)},
		"alias-policy-path":   {FlagName: "alias-policy-path", Set: setString(aliasPolicyPath)},
		"active-profile-path": {FlagName: "active-profile-path", Set: setString(activeProfilePath)},
	}); err != nil {
		log.Fatalf("config: %v", err)
	}
	if *initConfig {
		keyCreated, err := ensureSSHKeyMaterial(strings.TrimSpace(*keyPath), strings.TrimSpace(*user))
		if err != nil {
			log.Fatalf("init key setup: %v", err)
		}
		knownHostsCreated, err := ensureFileExists(strings.TrimSpace(*knownHostsPath), 0600)
		if err != nil {
			log.Fatalf("init known_hosts setup: %v", err)
		}
		if err := os.MkdirAll(strings.TrimSpace(*maildirRoot), 0700); err != nil {
			log.Fatalf("init maildir path: %v", err)
		}
		if err := os.MkdirAll(effectiveChatDir(strings.TrimSpace(*chatDir), strings.TrimSpace(*user)), 0700); err != nil {
			log.Fatalf("init chat dir: %v", err)
		}
		if err := os.MkdirAll(filepath.Dir(strings.TrimSpace(*knownKeysPath)), 0700); err != nil {
			log.Fatalf("init known keys path: %v", err)
		}
		if err := os.MkdirAll(filepath.Dir(strings.TrimSpace(*aliasPolicyPath)), 0700); err != nil {
			log.Fatalf("init alias policy path: %v", err)
		}
		if err := os.MkdirAll(filepath.Dir(strings.TrimSpace(*chatContactsPath)), 0700); err != nil {
			log.Fatalf("init chat contacts path: %v", err)
		}
		if err := writeCoreConfig(*configPath, coreConfigValues{
			Profile:           strings.TrimSpace(*profile),
			Relay:             strings.TrimSpace(*relayAddr),
			User:              strings.TrimSpace(*user),
			Zone:              strings.TrimSpace(*zone),
			Key:               strings.TrimSpace(*keyPath),
			KnownHosts:        strings.TrimSpace(*knownHostsPath),
			InsecureHostKey:   *insecureHostKey,
			SMTPListen:        strings.TrimSpace(*smtpListen),
			TLSPolicy:         strings.TrimSpace(*tlsPolicy),
			ACMEDNS01:         *acmeDNS01Enabled,
			ACMEViaRelay:      *acmeViaRelay,
			Shell:             *shellMode,
			Maildir:           strings.TrimSpace(*maildirRoot),
			ChatDir:           strings.TrimSpace(*chatDir),
			KnownKeys:         strings.TrimSpace(*knownKeysPath),
			AliasPolicyPath:   strings.TrimSpace(*aliasPolicyPath),
			ChatContacts:      strings.TrimSpace(*chatContactsPath),
			ActiveProfilePath: strings.TrimSpace(*activeProfilePath),
		}); err != nil {
			log.Fatalf("write config: %v", err)
		}
		log.Printf("wrote config: %s", *configPath)
		if keyCreated {
			log.Printf("created ssh key pair: %s (+ .pub)", strings.TrimSpace(*keyPath))
		}
		if knownHostsCreated {
			log.Printf("created known_hosts file: %s", strings.TrimSpace(*knownHostsPath))
		}
		log.Printf("initialized local paths: maildir=%s chat=%s", strings.TrimSpace(*maildirRoot), effectiveChatDir(strings.TrimSpace(*chatDir), strings.TrimSpace(*user)))
		log.Printf("next step: run `sisumail`")
		return
	}

	if *doctor || *doctorFull {
		code := runClientDoctorFull(strings.TrimSpace(*keyPath), strings.TrimSpace(*knownHostsPath), strings.TrimSpace(*configPath), strings.TrimSpace(*relayAddr), *insecureHostKey, *doctorFull)
		if code != 0 {
			os.Exit(code)
		}
		return
	}
	if err := writeActiveProfile(strings.TrimSpace(*activeProfilePath), strings.TrimSpace(*profile)); err != nil {
		log.Printf("warning: remember active profile failed: %v", err)
	}
	if *tuiMode && strings.TrimSpace(*chatWith) != "" {
		log.Fatalf("-tui and -chat-with both use stdin; choose one")
	}
	if *shellMode && (*tuiMode || strings.TrimSpace(*chatWith) != "") {
		log.Fatalf("-shell, -tui and -chat-with all use stdin; choose one")
	}

	store := &maildir.Store{Root: *maildirRoot}
	if err := store.Init(); err != nil {
		log.Fatalf("maildir init: %v", err)
	}
	chats := &chatlog.Store{Root: effectiveChatDir(strings.TrimSpace(*chatDir), strings.TrimSpace(*user))}
	if err := chats.Init(); err != nil {
		log.Fatalf("chatlog init: %v", err)
	}
	known := &knownkeys.Store{Path: *knownKeysPath}
	aliases := newAliasPolicyStore(strings.TrimSpace(*aliasPolicyPath))
	if err := aliases.Init(); err != nil {
		log.Fatalf("alias policy init: %v", err)
	}
	contacts := newChatContactsStore(strings.TrimSpace(*chatContactsPath))
	if err := contacts.Init(); err != nil {
		log.Fatalf("chat contacts init: %v", err)
	}
	if strings.TrimSpace(*chatAllow) != "" {
		peer, err := contacts.Add(strings.TrimSpace(*chatAllow))
		if err != nil {
			log.Fatalf("chat-allow: %v", err)
		}
		log.Printf("chat contact allowed: %s", peer)
		return
	}
	if strings.TrimSpace(*chatDisallow) != "" {
		peer, err := contacts.Remove(strings.TrimSpace(*chatDisallow))
		if err != nil {
			log.Fatalf("chat-disallow: %v", err)
		}
		log.Printf("chat contact removed: %s", peer)
		return
	}
	if *chatContactsList {
		list := contacts.List()
		if len(list) == 0 {
			fmt.Println("no chat contacts")
		} else {
			for _, p := range list {
				fmt.Println(p)
			}
		}
		return
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
	if strings.TrimSpace(*chatHistory) != "" {
		if err := printChatHistory(chats, contacts, *chatHistory, *chatLimit); err != nil {
			log.Fatalf("chat-history: %v", err)
		}
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	sshKey, err := os.ReadFile(*keyPath)
	if err != nil {
		log.Fatalf("read key: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(sshKey)
	if err != nil {
		log.Fatalf("parse key: %v", err)
	}

	hostKeyCB, err := buildHostKeyCallback(*insecureHostKey, *knownHostsPath)
	if err != nil {
		log.Fatalf("host key callback: %v", err)
	}

	sshCfg := &ssh.ClientConfig{
		User:            *user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCB,
		Timeout:         10 * time.Second,
	}
	if strings.TrimSpace(*claimUsername) != "" {
		sshCfg.User = "claim"
	}

	client, err := ssh.Dial("tcp", *relayAddr, sshCfg)
	if err != nil {
		log.Fatalf("ssh dial: %v", err)
	}
	defer client.Close()
	log.Printf("connected to relay %s as %s", *relayAddr, sshCfg.User)

	if strings.TrimSpace(*claimUsername) != "" {
		if strings.TrimSpace(*claimInviteCode) == "" {
			log.Fatalf("-claim requires -claim-invite")
		}
		ch, reqs, err := client.OpenChannel("claim-v1", nil)
		if err != nil {
			log.Fatalf("claim channel: %v", err)
		}
		go ssh.DiscardRequests(reqs)
		pubText := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
		if err := proto.WriteClaimRequest(ch, proto.ClaimRequest{
			Username:   strings.TrimSpace(*claimUsername),
			PubKeyText: pubText,
			InviteCode: strings.TrimSpace(*claimInviteCode),
		}); err != nil {
			log.Fatalf("claim request: %v", err)
		}
		resp, err := proto.ReadClaimResponse(ch)
		_ = ch.Close()
		if err != nil {
			log.Fatalf("claim response: %v", err)
		}
		if !resp.OK {
			log.Fatalf("claim failed: %s", resp.Message)
		}
		fmt.Printf("claimed: %s\n", resp.Username)
		fmt.Printf("address: %s\n", resp.Address)
		if len(resp.Invites) > 0 {
			fmt.Println("invites:")
			for _, c := range resp.Invites {
				fmt.Printf("  %s\n", c)
			}
		}
		return
	}

	host := fmt.Sprintf("%s.v6.%s", *user, strings.TrimSuffix(*zone, "."))
	if *acmeDNS01Enabled {
		defaultDir := filepath.Join(os.Getenv("HOME"), ".local", "share", "sisumail", "tls")
		if strings.TrimSpace(*certPath) == "" {
			*certPath = filepath.Join(defaultDir, host+".crt.pem")
		}
		if strings.TrimSpace(*keyPemPath) == "" {
			*keyPemPath = filepath.Join(defaultDir, host+".key.pem")
		}
		if strings.TrimSpace(*acmeAccountKeyPath) == "" {
			*acmeAccountKeyPath = filepath.Join(defaultDir, "acme-account.pem")
		}
	}

	var primary tlsboot.Provider
	var acmePrimary *tlsboot.ACMEDNS01Provider
	if *acmeDNS01Enabled {
		acmePrimary = &tlsboot.ACMEDNS01Provider{
			Hostname:        host,
			ZoneName:        strings.TrimSuffix(*zone, "."),
			Email:           strings.TrimSpace(*acmeEmail),
			DirectoryURL:    strings.TrimSpace(*acmeDirectoryURL),
			CertPath:        *certPath,
			KeyPath:         *keyPemPath,
			AccountKeyPath:  *acmeAccountKeyPath,
			RenewBefore:     *acmeRenewBefore,
			PropagationWait: *acmePropagationWait,
			IssueTimeout:    *acmeIssueTimeout,
		}
		if *acmeViaRelay {
			presenter := &relayDNS01Presenter{client: client}
			acmePrimary.PresentDNS01 = presenter.Present
		} else {
			token := loadHCloudToken()
			if strings.TrimSpace(token) == "" {
				log.Fatalf("acme dns-01 direct mode requires HCLOUD_TOKEN or HETZNER_CLOUD_TOKEN")
			}
			acmePrimary.DNSProvider = hetznercloud.NewClient(token, strings.TrimSuffix(*zone, "."))
		}
		primary = acmePrimary
	} else if *certPath != "" && *keyPemPath != "" {
		primary = &tlsboot.DiskProvider{CertPath: *certPath, KeyPath: *keyPemPath}
	}
	pol := tlsboot.ParsePolicy(*tlsPolicy)
	var provider tlsboot.Provider
	switch pol {
	case tlsboot.PolicyStrict:
		provider = &tlsboot.StrictProvider{Primary: primary}
	default:
		provider = &tlsboot.PragmaticProvider{
			Hostnames:          []string{host, "localhost"},
			Primary:            primary,
			SelfSignedValidity: 24 * time.Hour,
		}
	}

	var res tlsboot.CertResult
	if acmePrimary != nil {
		start := time.Now()
		log.Printf("acme: bootstrap start host=%s via_relay=%v directory=%s", host, *acmeViaRelay, defaultIfEmpty(strings.TrimSpace(*acmeDirectoryURL), "letsencrypt-production"))
		res, err = provider.GetCertificate(time.Now())
		log.Printf("acme: bootstrap done in %s source=%s authenticated_ca=%v err=%v", time.Since(start).Round(time.Second), res.Source, res.AuthenticatedCA, err)
		if err != nil && *acmeViaRelay && isRelayACMEControlUnavailable(err) {
			log.Printf("acme: relay control channel unavailable; starting with temporary local cert so inbox can run now")
			log.Printf("acme: operator action needed on relay: enable acme-dns01 channel support")
			fallback := &tlsboot.PragmaticProvider{
				Hostnames:          []string{host, "localhost"},
				SelfSignedValidity: 24 * time.Hour,
			}
			res, err = fallback.GetCertificate(time.Now())
			log.Printf("acme: fallback bootstrap source=%s authenticated_ca=%v err=%v", res.Source, res.AuthenticatedCA, err)
		}
	} else {
		res, err = provider.GetCertificate(time.Now())
	}
	if err != nil {
		log.Fatalf("tls bootstrap (%s): %v", pol, err)
	}
	if !res.Encrypted {
		log.Fatalf("tls bootstrap (%s): no certificate available", pol)
	}

	certState := newTLSCertState(res.Cert)
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return certState.Get(), nil
		},
	}
	log.Printf("tls: source=%s authenticated_ca=%v", res.Source, res.AuthenticatedCA)
	if !res.AuthenticatedCA {
		log.Printf("setup note: using temporary local TLS cert right now.")
		log.Printf("setup note: for a publicly trusted cert, run `sisumail -init` and keep `acme-dns01=true`, `acme-via-relay=true`, `tls-policy=strict`.")
	}
	if strings.TrimSpace(*apiListen) != "" {
		token, created, err := ensureLocalAPIToken(*apiTokenPath)
		if err != nil {
			log.Fatalf("api token setup: %v", err)
		}
		if created {
			log.Printf("local api token created: %s", *apiTokenPath)
		}
		status := localAPIStatus{
			Profile:            strings.TrimSpace(*profile),
			User:               strings.TrimSpace(*user),
			Relay:              strings.TrimSpace(*relayAddr),
			TLSSource:          res.Source,
			TLSAuthenticatedCA: res.AuthenticatedCA,
			SMTPListen:         strings.TrimSpace(*smtpListen),
			APIListen:          strings.TrimSpace(*apiListen),
			StartedAt:          time.Now().UTC(),
		}
		go func() {
			sendChatFn := func(toUser, message string) error {
				if err := ensurePeerAllowed(contacts, toUser); err != nil {
					return err
				}
				if client == nil {
					return fmt.Errorf("relay connection unavailable")
				}
				if err := sendChat(client, known, toUser, message); err != nil {
					return err
				}
				return nil
			}
			if err := runLocalAPIServer(ctx, strings.TrimSpace(*apiListen), token, strings.TrimSpace(*apiTokenPath), strings.TrimSpace(*activeProfilePath), home, status, sendChatFn); err != nil {
				log.Printf("local api server error: %v", err)
				cancel()
			}
		}()
	}
	if acmePrimary != nil && *acmeCheckInterval > 0 {
		go runACMERenewLoop(ctx, acmePrimary, certState, *acmeCheckInterval)
	}

	// Start local SMTP daemon.
	bridge := newDeliveryMetaBridge()
	backend := &localBackend{store: store, bridge: bridge, aliases: aliases}
	srv := smtp.NewServer(backend)
	srv.Addr = *smtpListen
	srv.Domain = host
	srv.AllowInsecureAuth = false
	srv.EnableSMTPUTF8 = false
	srv.TLSConfig = tlsCfg
	srv.ReadTimeout = 30 * time.Second
	srv.WriteTimeout = 30 * time.Second
	srv.MaxMessageBytes = localSMTPMaxMessageBytes
	srv.MaxRecipients = 10

	go func() {
		log.Printf("local smtp daemon listening on %s (STARTTLS required)", *smtpListen)
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("smtp daemon error: %v", err)
			cancel()
		}
	}()

	// Accept channels from relay (smtp-delivery).
	go func() {
		chans := client.HandleChannelOpen("smtp-delivery")
		for ch := range chans {
			go handleChannel(ch, *smtpListen, bridge)
		}
	}()

	// Accept Tier 2 spool deliveries from relay.
	replayGuard := newSpoolReplayGuard(10000, 24*time.Hour)
	go func() {
		chans := client.HandleChannelOpen("spool-delivery")
		for ch := range chans {
			go handleSpoolChannel(ch, string(sshKey), store, aliases, replayGuard)
		}
	}()
	go func() {
		chans := client.HandleChannelOpen("chat-delivery")
		for ch := range chans {
			go handleChatDeliveryChannel(ch, string(sshKey), chats, contacts)
		}
	}()

	if strings.TrimSpace(*chatTo) != "" {
		if strings.TrimSpace(*chatMsg) == "" {
			log.Fatalf("-chat-msg is required with -chat-to")
		}
		if err := ensurePeerAllowed(contacts, *chatTo); err != nil {
			log.Fatalf("chat send blocked: %v", err)
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
		if err := runChatREPL(client, chats, known, contacts, *chatWith); err != nil {
			log.Printf("chat session failed: %v", err)
		}
		if !*tuiMode {
			cancel()
		}
	}
	if *shellMode {
		if err := runCommandShell(*user, store, client, chats, known, contacts); err != nil {
			log.Printf("shell failed: %v", err)
		}
		cancel()
	}

	if *tuiMode {
		if err := runInboxTUI(store, client, chats, known, contacts); err != nil {
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

func runACMERenewLoop(ctx context.Context, p *tlsboot.ACMEDNS01Provider, state *tlsCertState, interval time.Duration) {
	if p == nil || state == nil || interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			res, err := p.GetCertificate(time.Now())
			if err != nil {
				log.Printf("acme renew: %v", err)
				continue
			}
			if !res.Encrypted {
				log.Printf("acme renew: no certificate available")
				continue
			}
			if state.SetIfChanged(res.Cert) {
				log.Printf("acme renew: certificate updated (source=%s authenticated_ca=%v)", res.Source, res.AuthenticatedCA)
			}
		}
	}
}

func loadHCloudToken() string {
	if tok := strings.TrimSpace(os.Getenv("HCLOUD_TOKEN")); tok != "" {
		return tok
	}
	return strings.TrimSpace(os.Getenv("HETZNER_CLOUD_TOKEN"))
}

type tlsCertState struct {
	mu          sync.RWMutex
	cert        tls.Certificate
	fingerprint string
}

func newTLSCertState(cert tls.Certificate) *tlsCertState {
	s := &tlsCertState{}
	s.set(cert)
	return s
}

func (s *tlsCertState) Get() *tls.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cert
	return &c
}

func (s *tlsCertState) SetIfChanged(cert tls.Certificate) bool {
	fp := certFingerprint(cert)
	s.mu.Lock()
	defer s.mu.Unlock()
	if fp == s.fingerprint && fp != "" {
		return false
	}
	s.cert = cert
	s.fingerprint = fp
	return true
}

func (s *tlsCertState) set(cert tls.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cert = cert
	s.fingerprint = certFingerprint(cert)
}

func certFingerprint(cert tls.Certificate) string {
	if len(cert.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(sum[:])
}

func defaultIfEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func isUnsupportedChannelError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(strings.TrimSpace(err.Error()))
	if s == "" {
		return false
	}
	return strings.Contains(s, "unknown channel type") || strings.Contains(s, "unsupported")
}

func isRelayACMEControlUnavailable(err error) bool {
	return isUnsupportedChannelError(err)
}

func isRelayChatControlUnavailable(err error) bool {
	return isUnsupportedChannelError(err)
}

func normalizeChatSendError(err error) error {
	if err == nil {
		return nil
	}
	if isRelayChatControlUnavailable(err) {
		return fmt.Errorf("relay chat channel unavailable; operator action needed: enable chat-send/chat-delivery channels")
	}
	return err
}

func ensureSSHKeyMaterial(privatePath, user string) (bool, error) {
	privatePath = strings.TrimSpace(privatePath)
	if privatePath == "" {
		return false, fmt.Errorf("empty key path")
	}
	if _, err := os.Stat(privatePath); err == nil {
		if err := ensurePublicKeyFromPrivate(privatePath); err != nil {
			return false, err
		}
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}

	if err := os.MkdirAll(filepath.Dir(privatePath), 0700); err != nil {
		return false, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return false, err
	}
	comment := strings.TrimSpace(user)
	if comment == "" {
		comment = "sisumail"
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return false, err
	}
	pemBytes := pem.EncodeToMemory(block)
	if err := os.WriteFile(privatePath, pemBytes, 0600); err != nil {
		return false, err
	}
	if err := ensurePublicKeyFromPrivate(privatePath); err != nil {
		return false, err
	}
	return true, nil
}

func ensurePublicKeyFromPrivate(privatePath string) error {
	b, err := os.ReadFile(privatePath)
	if err != nil {
		return err
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return fmt.Errorf("parse private key %s: %w", privatePath, err)
	}
	pubPath := privatePath + ".pub"
	if _, err := os.Stat(pubPath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0644); err != nil {
		return err
	}
	return nil
}

func ensureFileExists(path string, mode os.FileMode) (bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return false, fmt.Errorf("empty path")
	}
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return false, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return false, err
	}
	if err := f.Close(); err != nil {
		return false, err
	}
	return true, nil
}

type aliasPolicyStore struct {
	Path    string
	mu      sync.RWMutex
	blocked map[string]bool
}

type chatContactsStore struct {
	Path    string
	mu      sync.RWMutex
	allowed map[string]bool
}

func newChatContactsStore(path string) *chatContactsStore {
	return &chatContactsStore{
		Path:    strings.TrimSpace(path),
		allowed: make(map[string]bool),
	}
}

func (s *chatContactsStore) Init() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowed = make(map[string]bool)
	if strings.TrimSpace(s.Path) == "" {
		return nil
	}
	b, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var doc struct {
		Allowed []string `json:"allowed"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return err
	}
	for _, p := range doc.Allowed {
		if n := normalizeChatPeer(p); n != "" {
			s.allowed[n] = true
		}
	}
	return nil
}

func (s *chatContactsStore) IsAllowed(peer string) bool {
	if s == nil {
		return true
	}
	n := normalizeChatPeer(peer)
	if n == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.allowed[n]
}

func (s *chatContactsStore) Add(peer string) (string, error) {
	if s == nil {
		return "", fmt.Errorf("chat contacts unavailable")
	}
	n := normalizeChatPeer(peer)
	if n == "" {
		return "", fmt.Errorf("invalid peer")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowed[n] = true
	return n, s.persistLocked()
}

func (s *chatContactsStore) Remove(peer string) (string, error) {
	if s == nil {
		return "", fmt.Errorf("chat contacts unavailable")
	}
	n := normalizeChatPeer(peer)
	if n == "" {
		return "", fmt.Errorf("invalid peer")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.allowed, n)
	return n, s.persistLocked()
}

func (s *chatContactsStore) List() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.allowed))
	for k := range s.allowed {
		out = append(out, k)
	}
	return out
}

func (s *chatContactsStore) persistLocked() error {
	if strings.TrimSpace(s.Path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0700); err != nil {
		return err
	}
	list := make([]string, 0, len(s.allowed))
	for k := range s.allowed {
		list = append(list, k)
	}
	doc := struct {
		Allowed []string `json:"allowed"`
	}{Allowed: list}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.Path, b, 0600)
}

func newAliasPolicyStore(path string) *aliasPolicyStore {
	return &aliasPolicyStore{
		Path:    strings.TrimSpace(path),
		blocked: make(map[string]bool),
	}
}

func (s *aliasPolicyStore) Init() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocked = make(map[string]bool)
	if strings.TrimSpace(s.Path) == "" {
		return nil
	}
	b, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var doc struct {
		Blocked []string `json:"blocked"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return err
	}
	for _, a := range doc.Blocked {
		if n := normalizeAlias(a); n != "" {
			s.blocked[n] = true
		}
	}
	return nil
}

func (s *aliasPolicyStore) IsBlocked(alias string) bool {
	if s == nil {
		return false
	}
	n := normalizeAlias(alias)
	if n == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.blocked[n]
}

func (s *aliasPolicyStore) Block(alias string) error {
	if s == nil {
		return fmt.Errorf("alias policy unavailable")
	}
	n := normalizeAlias(alias)
	if n == "" {
		return fmt.Errorf("invalid alias")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocked[n] = true
	return s.persistLocked()
}

func (s *aliasPolicyStore) Unblock(alias string) error {
	if s == nil {
		return fmt.Errorf("alias policy unavailable")
	}
	n := normalizeAlias(alias)
	if n == "" {
		return fmt.Errorf("invalid alias")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.blocked, n)
	return s.persistLocked()
}

func (s *aliasPolicyStore) persistLocked() error {
	if strings.TrimSpace(s.Path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0700); err != nil {
		return err
	}
	list := make([]string, 0, len(s.blocked))
	for k := range s.blocked {
		list = append(list, k)
	}
	doc := struct {
		Blocked []string `json:"blocked"`
	}{Blocked: list}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.Path, b, 0600)
}

func normalizeAlias(alias string) string {
	alias = strings.ToLower(strings.TrimSpace(alias))
	if alias == "" {
		return ""
	}
	for _, r := range alias {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' || r == '+' {
			continue
		}
		return ""
	}
	return alias
}

func normalizeChatPeer(raw string) string {
	p := strings.ToLower(strings.TrimSpace(raw))
	if p == "" {
		return ""
	}
	for _, r := range p {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return ""
	}
	return p
}

func ensurePeerAllowed(contacts *chatContactsStore, peer string) error {
	p := normalizeChatPeer(peer)
	if p == "" {
		return fmt.Errorf("invalid peer")
	}
	if contacts == nil {
		return nil
	}
	if !contacts.IsAllowed(p) {
		return fmt.Errorf("peer %q not in allowlist", p)
	}
	return nil
}

func sanitizeLocalName(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return "default"
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
	}
	out := strings.Trim(b.String(), "-_.")
	if out == "" {
		return "default"
	}
	return out
}

func effectiveChatDir(baseDir, user string) string {
	base := strings.TrimSpace(baseDir)
	if base == "" {
		return ""
	}
	return filepath.Join(base, "users", sanitizeLocalName(user))
}

func aliasFromAddress(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, ",") {
		if list, err := mail.ParseAddressList(raw); err == nil && len(list) > 0 {
			raw = list[0].Address
		}
	}
	if parsed, err := mail.ParseAddress(raw); err == nil {
		raw = parsed.Address
	}
	at := strings.IndexByte(raw, '@')
	if at <= 0 || at >= len(raw)-1 {
		return ""
	}
	return normalizeAlias(raw[:at])
}

func aliasFromMessageHeaders(h mail.Header) string {
	if h == nil {
		return ""
	}
	if a := normalizeAlias(h.Get("X-Sisumail-Alias")); a != "" {
		return a
	}
	for _, k := range []string{"Delivered-To", "X-Original-To", "To"} {
		if a := aliasFromAddress(h.Get(k)); a != "" {
			return a
		}
	}
	return ""
}

func ensureLocalAPIToken(path string) (token string, created bool, err error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", false, fmt.Errorf("empty api token path")
	}
	if b, readErr := os.ReadFile(path); readErr == nil {
		t := strings.TrimSpace(string(b))
		if t == "" {
			return "", false, fmt.Errorf("api token file is empty: %s", path)
		}
		return t, false, nil
	} else if !os.IsNotExist(readErr) {
		return "", false, readErr
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", false, err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", false, err
	}
	t := hex.EncodeToString(raw)
	if err := os.WriteFile(path, []byte(t+"\n"), 0600); err != nil {
		return "", false, err
	}
	return t, true, nil
}

func newLocalSessionToken() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

type localAPIStatus struct {
	Profile            string    `json:"profile"`
	User               string    `json:"user"`
	Relay              string    `json:"relay"`
	TLSSource          string    `json:"tls_source"`
	TLSAuthenticatedCA bool      `json:"tls_authenticated_ca"`
	SMTPListen         string    `json:"smtp_listen"`
	APIListen          string    `json:"api_listen"`
	StartedAt          time.Time `json:"started_at"`
}

type apiInboxItem struct {
	ID      string `json:"id"`
	Tier    string `json:"tier"`
	State   string `json:"state"`
	Trust   string `json:"trust"`
	Alias   string `json:"alias"`
	From    string `json:"from"`
	Subject string `json:"subject"`
}

type profileContext struct {
	Profile  string
	User     string
	Store    *maildir.Store
	Chats    *chatlog.Store
	Aliases  *aliasPolicyStore
	Contacts *chatContactsStore
}

func profileConfigPath(home, profile string) string {
	p := normalizeProfileName(profile)
	if p == "default" {
		return filepath.Join(home, ".config", "sisumail", "config.env")
	}
	return filepath.Join(home, ".config", "sisumail", "profiles", p, "config.env")
}

func openProfileContext(home, profile string) (*profileContext, error) {
	p := normalizeProfileName(profile)
	if p == "" {
		p = "default"
	}
	def := defaultsForProfile(home, p)
	cfg, err := readConfigFile(profileConfigPath(home, p))
	if err != nil {
		return nil, err
	}
	user := strings.TrimSpace(cfg["user"])
	if user == "" {
		if p == "default" {
			user = "niklas"
		} else {
			user = p
		}
	}
	mailRoot := strings.TrimSpace(cfg["maildir"])
	if mailRoot == "" {
		mailRoot = def.MaildirRoot
	}
	chatDir := strings.TrimSpace(cfg["chat-dir"])
	if chatDir == "" {
		chatDir = def.ChatDir
	}
	chatDir = effectiveChatDir(chatDir, user)
	aliasPath := strings.TrimSpace(cfg["alias-policy-path"])
	if aliasPath == "" {
		aliasPath = def.AliasPolicyPath
	}
	contactsPath := strings.TrimSpace(cfg["chat-contacts-path"])
	if contactsPath == "" {
		contactsPath = def.ChatContactsPath
	}
	store := &maildir.Store{Root: mailRoot}
	if err := store.Init(); err != nil {
		return nil, err
	}
	chats := &chatlog.Store{Root: chatDir}
	if err := chats.Init(); err != nil {
		return nil, err
	}
	aliases := newAliasPolicyStore(aliasPath)
	if err := aliases.Init(); err != nil {
		return nil, err
	}
	contacts := newChatContactsStore(contactsPath)
	if err := contacts.Init(); err != nil {
		return nil, err
	}
	return &profileContext{
		Profile:  p,
		User:     user,
		Store:    store,
		Chats:    chats,
		Aliases:  aliases,
		Contacts: contacts,
	}, nil
}

func runLocalAPIServer(ctx context.Context, addr, token, tokenPath, activeProfilePath, home string, status localAPIStatus, sendChatFn func(string, string) error) error {
	if strings.TrimSpace(addr) == "" {
		return nil
	}
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("missing api token")
	}
	apiMux := http.NewServeMux()
	appSessionToken, err := newLocalSessionToken()
	if err != nil {
		return err
	}
	resolveProfile := func(r *http.Request) (*profileContext, error) {
		p := normalizeProfileName(r.URL.Query().Get("profile"))
		if p == "" {
			p = status.Profile
		}
		return openProfileContext(home, p)
	}
	statusHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		pc, err := resolveProfile(r)
		if err != nil {
			http.Error(w, "profile unavailable", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"profile":              pc.Profile,
			"user":                 pc.User,
			"runtime_profile":      status.Profile,
			"view_only":            pc.Profile != status.Profile,
			"relay":                status.Relay,
			"tls_source":           status.TLSSource,
			"tls_authenticated_ca": status.TLSAuthenticatedCA,
			"smtp_listen":          status.SMTPListen,
			"api_listen":           status.APIListen,
			"started_at":           status.StartedAt,
		})
	}
	profilesHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		type profileItem struct {
			Profile string `json:"profile"`
			User    string `json:"user"`
			Address string `json:"address"`
		}
		names := listProfiles(home, status.Profile)
		items := make([]profileItem, 0, len(names))
		for _, p := range names {
			u := profileUser(home, p)
			addr := ""
			if u != "" {
				addr = "inbox@" + u + ".sisumail.fi"
			}
			items = append(items, profileItem{Profile: p, User: u, Address: addr})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"current":  status.Profile,
			"profiles": items,
		})
	}
	selectProfileHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Profile string `json:"profile"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json body", http.StatusBadRequest)
			return
		}
		p := normalizeProfileName(req.Profile)
		if p == "" {
			http.Error(w, "invalid profile", http.StatusBadRequest)
			return
		}
		if err := writeActiveProfile(activeProfilePath, p); err != nil {
			http.Error(w, "cannot persist active profile", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "profile": p, "restart_required": true})
	}
	inboxHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		pc, err := resolveProfile(r)
		if err != nil || pc.Store == nil {
			writeJSON(w, http.StatusOK, []apiInboxItem{})
			return
		}
		entries, err := pc.Store.List()
		if err != nil {
			http.Error(w, "inbox unavailable", http.StatusInternalServerError)
			return
		}
		items := make([]apiInboxItem, 0, len(entries))
		for _, e := range entries {
			s := readSummaryInfo(pc.Store, e.ID, e.Tier)
			state := "unread"
			if e.Seen {
				state = "read"
			}
			items = append(items, apiInboxItem{
				ID:      e.ID,
				Tier:    strings.ToUpper(e.Tier),
				State:   state,
				Trust:   s.Trust,
				Alias:   s.Alias,
				From:    s.From,
				Subject: s.Subject,
			})
		}
		writeJSON(w, http.StatusOK, items)
	}
	messageHandler := func(prefix string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			pc, err := resolveProfile(r)
			if err != nil || pc.Store == nil {
				http.Error(w, "message not found", http.StatusNotFound)
				return
			}
			id := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, prefix))
			if id == "" {
				http.Error(w, "missing message id", http.StatusBadRequest)
				return
			}
			rc, err := pc.Store.Read(id)
			if err != nil {
				http.Error(w, "message not found", http.StatusNotFound)
				return
			}
			defer rc.Close()
			w.Header().Set("Content-Type", "message/rfc822; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = io.Copy(w, rc)
		}
	}
	messageActionHandler := func(action string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			pc, err := resolveProfile(r)
			if err != nil || pc.Store == nil {
				http.Error(w, "message not found", http.StatusNotFound)
				return
			}
			base := "/app/v1/message/"
			rest := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, base))
			if rest == "" {
				http.Error(w, "missing message id", http.StatusBadRequest)
				return
			}
			parts := strings.Split(rest, "/")
			if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || parts[1] != action {
				http.Error(w, "bad message action path", http.StatusBadRequest)
				return
			}
			id := strings.TrimSpace(parts[0])
			var actionErr error
			switch action {
			case "read":
				actionErr = pc.Store.MarkRead(id)
			case "archive":
				actionErr = pc.Store.Archive(id)
			case "delete":
				actionErr = pc.Store.Delete(id)
			default:
				http.Error(w, "unsupported action", http.StatusBadRequest)
				return
			}
			if actionErr != nil {
				http.Error(w, "message action failed", http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "action": action})
		}
	}
	messageViewHandler := func(prefix string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			pc, err := resolveProfile(r)
			if err != nil || pc.Store == nil {
				http.Error(w, "message not found", http.StatusNotFound)
				return
			}
			id := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, prefix))
			if id == "" {
				http.Error(w, "missing message id", http.StatusBadRequest)
				return
			}
			rc, err := pc.Store.Read(id)
			if err != nil {
				http.Error(w, "message not found", http.StatusNotFound)
				return
			}
			defer rc.Close()
			raw, err := io.ReadAll(io.LimitReader(rc, 8<<20))
			if err != nil {
				http.Error(w, "message read failed", http.StatusInternalServerError)
				return
			}
			view := parseMessageView(id, raw)
			writeJSON(w, http.StatusOK, view)
		}
	}
	chatHistoryHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		peer := strings.TrimSpace(r.URL.Query().Get("peer"))
		if peer == "" {
			http.Error(w, "missing peer", http.StatusBadRequest)
			return
		}
		pc, err := resolveProfile(r)
		if err != nil || pc.Chats == nil {
			http.Error(w, "chat unavailable", http.StatusInternalServerError)
			return
		}
		if err := ensurePeerAllowed(pc.Contacts, peer); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		limit := 50
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 || n > 500 {
				http.Error(w, "bad limit", http.StatusBadRequest)
				return
			}
			limit = n
		}
		type row struct {
			Direction string    `json:"direction"`
			Message   string    `json:"message"`
			At        time.Time `json:"at"`
		}
		list, err := pc.Chats.List(peer, limit)
		if err != nil {
			http.Error(w, "chat unavailable", http.StatusInternalServerError)
			return
		}
		out := make([]row, 0, len(list))
		for _, e := range list {
			out = append(out, row{Direction: e.Direction, Message: e.Message, At: e.At.UTC()})
		}
		writeJSON(w, http.StatusOK, out)
	}
	chatSendHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if sendChatFn == nil {
			http.Error(w, "chat send unavailable", http.StatusServiceUnavailable)
			return
		}
		var req struct {
			To      string `json:"to"`
			Message string `json:"message"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json body", http.StatusBadRequest)
			return
		}
		req.To = strings.TrimSpace(req.To)
		req.Message = strings.TrimSpace(req.Message)
		if req.To == "" || req.Message == "" {
			http.Error(w, "missing to/message", http.StatusBadRequest)
			return
		}
		pc, err := resolveProfile(r)
		if err != nil {
			http.Error(w, "profile unavailable", http.StatusInternalServerError)
			return
		}
		if err := ensurePeerAllowed(pc.Contacts, req.To); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if pc.Profile != status.Profile {
			http.Error(w, "selected profile is view-only in this running session", http.StatusConflict)
			return
		}
		if err := sendChatFn(req.To, req.Message); err != nil {
			http.Error(w, "chat send failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		if pc.Chats != nil {
			_ = pc.Chats.Append(req.To, "out", req.Message, time.Now())
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
	chatContactsHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		pc, err := resolveProfile(r)
		if err != nil || pc.Contacts == nil {
			writeJSON(w, http.StatusOK, []string{})
			return
		}
		writeJSON(w, http.StatusOK, pc.Contacts.List())
	}
	chatContactsMutateHandler := func(add bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			pc, err := resolveProfile(r)
			if err != nil || pc.Contacts == nil {
				http.Error(w, "chat contacts unavailable", http.StatusServiceUnavailable)
				return
			}
			var req struct {
				Peer string `json:"peer"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad json body", http.StatusBadRequest)
				return
			}
			var peer string
			if add {
				peer, err = pc.Contacts.Add(req.Peer)
			} else {
				peer, err = pc.Contacts.Remove(req.Peer)
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "peer": peer, "allowed": add})
		}
	}
	aliasBlockHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		pc, err := resolveProfile(r)
		if err != nil || pc.Aliases == nil {
			http.Error(w, "alias policy unavailable", http.StatusServiceUnavailable)
			return
		}
		var req struct {
			Alias string `json:"alias"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json body", http.StatusBadRequest)
			return
		}
		a := normalizeAlias(req.Alias)
		if a == "" {
			http.Error(w, "invalid alias", http.StatusBadRequest)
			return
		}
		if err := pc.Aliases.Block(a); err != nil {
			http.Error(w, "alias block failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "alias": a, "blocked": true})
	}
	aliasUnblockHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		pc, err := resolveProfile(r)
		if err != nil || pc.Aliases == nil {
			http.Error(w, "alias policy unavailable", http.StatusServiceUnavailable)
			return
		}
		var req struct {
			Alias string `json:"alias"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json body", http.StatusBadRequest)
			return
		}
		a := normalizeAlias(req.Alias)
		if a == "" {
			http.Error(w, "invalid alias", http.StatusBadRequest)
			return
		}
		if err := pc.Aliases.Unblock(a); err != nil {
			http.Error(w, "alias unblock failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "alias": a, "blocked": false})
	}
	apiMux.HandleFunc("/v1/status", statusHandler)
	apiMux.HandleFunc("/v1/profiles", profilesHandler)
	apiMux.HandleFunc("/v1/profiles/select", selectProfileHandler)
	apiMux.HandleFunc("/v1/inbox", inboxHandler)
	apiMux.HandleFunc("/v1/message/", messageHandler("/v1/message/"))
	apiMux.HandleFunc("/v1/chat/history", chatHistoryHandler)
	apiMux.HandleFunc("/v1/chat/send", chatSendHandler)
	apiMux.HandleFunc("/v1/chat/contacts", chatContactsHandler)
	apiMux.HandleFunc("/v1/chat/contacts/add", chatContactsMutateHandler(true))
	apiMux.HandleFunc("/v1/chat/contacts/remove", chatContactsMutateHandler(false))
	apiMux.HandleFunc("/v1/alias/block", aliasBlockHandler)
	apiMux.HandleFunc("/v1/alias/unblock", aliasUnblockHandler)

	// App routes: no token prompt, but only loopback clients may use these.
	appMux := http.NewServeMux()
	appMux.HandleFunc("/app/v1/status", statusHandler)
	appMux.HandleFunc("/app/v1/profiles", profilesHandler)
	appMux.HandleFunc("/app/v1/profiles/select", selectProfileHandler)
	appMux.HandleFunc("/app/v1/inbox", inboxHandler)
	appMux.HandleFunc("/app/v1/message-view/", messageViewHandler("/app/v1/message-view/"))
	appMux.HandleFunc("/app/v1/message/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimSpace(r.URL.Path)
		if strings.HasSuffix(path, "/read") {
			messageActionHandler("read")(w, r)
			return
		}
		if strings.HasSuffix(path, "/archive") {
			messageActionHandler("archive")(w, r)
			return
		}
		if strings.HasSuffix(path, "/delete") {
			messageActionHandler("delete")(w, r)
			return
		}
		messageHandler("/app/v1/message/")(w, r)
	})
	appMux.HandleFunc("/app/v1/chat/history", chatHistoryHandler)
	appMux.HandleFunc("/app/v1/chat/send", chatSendHandler)
	appMux.HandleFunc("/app/v1/chat/contacts", chatContactsHandler)
	appMux.HandleFunc("/app/v1/chat/contacts/add", chatContactsMutateHandler(true))
	appMux.HandleFunc("/app/v1/chat/contacts/remove", chatContactsMutateHandler(false))
	appMux.HandleFunc("/app/v1/alias/block", aliasBlockHandler)
	appMux.HandleFunc("/app/v1/alias/unblock", aliasUnblockHandler)

	appWithSession := withAppSessionToken(appSessionToken, appMux)
	loopbackOnlyApp := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackRequest(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		appWithSession.ServeHTTP(w, r)
	})

	rootMux := http.NewServeMux()
	rootMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/app/inbox", http.StatusFound)
	})
	rootMux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app/inbox", http.StatusFound)
	})
	rootMux.HandleFunc("/app/inbox", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, strings.ReplaceAll(localInboxAppHTML, "__APP_SESSION_TOKEN__", appSessionToken))
	})
	rootMux.HandleFunc("/app/chat", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, strings.ReplaceAll(localChatAppHTML, "__APP_SESSION_TOKEN__", appSessionToken))
	})
	rootMux.Handle("/app/v1/", loopbackOnlyApp)
	rootMux.Handle("/v1/", withBearerToken(token, apiMux))

	srv := &http.Server{
		Addr:              addr,
		Handler:           rootMux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Printf("local api listening on %s", addr)
	log.Printf("local api auth: Bearer token from %s", tokenPath)
	err = srv.ListenAndServe()
	if err == nil || err == http.ErrServerClosed {
		return nil
	}
	return err
}

type apiMessageView struct {
	ID      string `json:"id"`
	From    string `json:"from"`
	Subject string `json:"subject"`
	Date    string `json:"date"`
	Alias   string `json:"alias"`
	Body    string `json:"body"`
}

func parseMessageView(id string, raw []byte) apiMessageView {
	out := apiMessageView{
		ID:      strings.TrimSpace(id),
		From:    "Unknown sender",
		Subject: "(no subject)",
	}
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		out.Body = strings.TrimSpace(string(raw))
		if out.Body == "" {
			out.Body = "(empty message)"
		}
		return out
	}
	if v := strings.TrimSpace(m.Header.Get("From")); v != "" {
		out.From = v
	}
	if v := strings.TrimSpace(m.Header.Get("Subject")); v != "" {
		out.Subject = v
	}
	out.Date = strings.TrimSpace(m.Header.Get("Date"))
	out.Alias = aliasFromMessageHeaders(m.Header)
	body := strings.TrimSpace(extractReadableBody(mail.Header(m.Header), m.Body))
	if body == "" {
		body = "(empty message)"
	}
	out.Body = body
	return out
}

func extractReadableBody(h mail.Header, r io.Reader) string {
	ct := strings.TrimSpace(h.Get("Content-Type"))
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil || mediaType == "" {
		mediaType = "text/plain"
	}
	encoding := strings.ToLower(strings.TrimSpace(h.Get("Content-Transfer-Encoding")))
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := strings.TrimSpace(params["boundary"])
		if boundary == "" {
			b, _ := io.ReadAll(decodeBodyByEncoding(r, encoding))
			return strings.TrimSpace(string(b))
		}
		mr := multipart.NewReader(r, boundary)
		var plain string
		var html string
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			partText := strings.TrimSpace(extractReadableBody(mail.Header(part.Header), part))
			if partText == "" {
				continue
			}
			pct := strings.ToLower(strings.TrimSpace(part.Header.Get("Content-Type")))
			if strings.Contains(pct, "text/plain") && plain == "" {
				plain = partText
				continue
			}
			if strings.Contains(pct, "text/html") && html == "" {
				html = stripHTMLToText(partText)
			}
		}
		if plain != "" {
			return plain
		}
		if html != "" {
			return html
		}
		return ""
	}
	b, _ := io.ReadAll(decodeBodyByEncoding(r, encoding))
	text := string(b)
	if strings.Contains(strings.ToLower(mediaType), "text/html") {
		text = stripHTMLToText(text)
	}
	return strings.TrimSpace(text)
}

func decodeBodyByEncoding(r io.Reader, encoding string) io.Reader {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, r)
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	default:
		return r
	}
}

func stripHTMLToText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "<br>", "\n")
	s = strings.ReplaceAll(s, "<br/>", "\n")
	s = strings.ReplaceAll(s, "<br />", "\n")
	s = strings.ReplaceAll(s, "</p>", "\n")
	var b strings.Builder
	inTag := false
	for _, r := range s {
		switch r {
		case '<':
			inTag = true
		case '>':
			inTag = false
		default:
			if !inTag {
				b.WriteRune(r)
			}
		}
	}
	out := b.String()
	out = strings.ReplaceAll(out, "&nbsp;", " ")
	out = strings.ReplaceAll(out, "&amp;", "&")
	out = strings.ReplaceAll(out, "&lt;", "<")
	out = strings.ReplaceAll(out, "&gt;", ">")
	out = strings.ReplaceAll(out, "&quot;", "\"")
	out = strings.ReplaceAll(out, "&#39;", "'")
	return strings.TrimSpace(out)
}

func withBearerToken(token string, next http.Handler) http.Handler {
	want := "Bearer " + strings.TrimSpace(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(r.Header.Get("Authorization")) != want {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func withAppSessionToken(token string, next http.Handler) http.Handler {
	want := strings.TrimSpace(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(r.Header.Get("X-Sisu-App-Token")) != want {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isLoopbackRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

const localAppHomeHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Sisu Mail</title>
  <style>
    :root { --sand:#f7f2e7; --ink:#1f1a17; --muted:#655d56; --line:#d9cfbe; --card:#fff9ef; --mint:#1b7d64; --mint2:#0f5f4b; --sky:#dbeeff; }
    * { box-sizing:border-box; }
    body { margin:0; color:var(--ink); font-family:"Avenir Next","Trebuchet MS","Segoe UI",sans-serif; background:radial-gradient(1000px 420px at 15% -10%, #fff9da 0%, transparent 65%),radial-gradient(900px 320px at 88% -8%, #d9f2e8 0%, transparent 62%),var(--sand); }
    .wrap { max-width:980px; margin:0 auto; padding:26px; }
    .title { margin:0; font-size:38px; } .sub { margin:8px 0 0; color:var(--muted); font-size:18px; }
    .status { margin-top:14px; display:flex; gap:8px; flex-wrap:wrap; }
    .chip { background:#f0eadc; border:1px solid var(--line); border-radius:999px; padding:6px 10px; font-size:12px; }
    .chip.good { background:#e6f7f1; border-color:#b7e3d7; color:#0f5f4b; }
    .grid { margin-top:16px; display:grid; grid-template-columns:1fr 1fr; gap:12px; }
    .card { display:block; text-decoration:none; color:inherit; background:var(--card); border:1px solid var(--line); border-radius:16px; padding:18px; box-shadow:0 1px 0 rgba(0,0,0,.03); }
    .card:hover { transform:translateY(-1px); transition:.15s ease; }
    .card h2 { margin:0; font-size:26px; }
    .card p { margin:8px 0 0; color:var(--muted); }
    .inbox { background:linear-gradient(160deg,#fff8e8,#fffdf7); }
    .chat { background:linear-gradient(160deg,#ecf8ff,#f9fdff); border-color:#cde3f2; }
    .addr { margin-top:16px; background:white; border:1px dashed var(--line); border-radius:12px; padding:12px; font-weight:700; }
    @media (max-width: 820px) { .grid { grid-template-columns:1fr; } .title { font-size:32px; } }
  </style>
</head>
<body>
  <div class="wrap">
    <h1 class="title">Sisu Mail</h1>
    <p class="sub">Choose what you want to do.</p>
    <div class="status">
      <span id="chip-conn" class="chip">Checking connection...</span>
      <span id="chip-tls" class="chip">Checking security...</span>
      <span class="chip">Receive-only email identity</span>
    </div>
    <div id="addr" class="addr">Address: inbox@&lt;user&gt;.sisumail.fi</div>
    <div class="grid">
      <a class="card inbox" href="/app/inbox">
        <h2>Open Inbox</h2>
        <p>Read mail, manage aliases, mark/archive/delete messages.</p>
      </a>
      <a class="card chat" href="/app/chat">
        <h2>Open Chat</h2>
        <p>Optional encrypted chat for coordination.</p>
      </a>
    </div>
  </div>
  <script>
    async function api(path) { const r = await fetch(path); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
    (async () => {
      try {
        const j = await api('/app/v1/status');
        const conn = document.getElementById('chip-conn');
        const tls = document.getElementById('chip-tls');
        conn.textContent = 'Connected';
        conn.className = 'chip good';
        tls.textContent = j.tls_authenticated_ca ? 'Secure (Verified CA)' : 'Secure (Temporary cert)';
        if (j.tls_authenticated_ca) tls.className = 'chip good';
        document.getElementById('addr').textContent = 'Address: inbox@' + j.user + '.sisumail.fi';
      } catch {
        document.getElementById('chip-conn').textContent = 'Offline';
        document.getElementById('chip-tls').textContent = 'Unknown';
      }
    })();
  </script>
</body>
</html>`

const localInboxAppHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Sisu Inbox</title>
  <style>
    :root { --sand:#f7f2e7; --ink:#1f1a17; --muted:#655d56; --line:#d9cfbe; --card:#fff9ef; --mint:#1b7d64; --mint2:#0f5f4b; --red:#922; }
    * { box-sizing:border-box; }
    body { margin:0; color:var(--ink); font-family:"Avenir Next","Trebuchet MS","Segoe UI",sans-serif; background:radial-gradient(1000px 400px at 20% -10%, #fff9da 0%, transparent 65%),radial-gradient(800px 300px at 85% -5%, #d9f2e8 0%, transparent 60%),var(--sand); }
    .wrap { max-width:1160px; margin:0 auto; padding:22px; }
    .hero { display:flex; justify-content:space-between; gap:16px; align-items:flex-start; flex-wrap:wrap; }
    .title { margin:0; font-size:34px; }
    .sub { margin:5px 0 0; color:var(--muted); }
    .chips,.nav,.toolbar,.aliases { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
    .chip,.nav a,.alias-btn { background:#f0eadc; border:1px solid var(--line); border-radius:999px; padding:6px 10px; font-size:12px; text-decoration:none; color:inherit; }
    .nav a.active,.chip.good,.alias-btn.active { background:#e6f7f1; border-color:#b7e3d7; color:#0f5f4b; }
    .card { background:var(--card); border:1px solid var(--line); border-radius:14px; padding:14px; box-shadow:0 1px 0 rgba(0,0,0,.03); }
    .account { margin-top:12px; display:block; }
    .addr-switch { font-size:18px; font-weight:700; border:1px solid #b7e3d7; background:#f2fff9; color:#0f5f4b; border-radius:12px; padding:10px 12px; min-width:360px; max-width:100%; }
    button { font:inherit; border:1px solid var(--line); border-radius:10px; padding:8px 10px; background:white; cursor:pointer; }
    button.primary { background:linear-gradient(180deg,var(--mint),var(--mint2)); color:white; border:none; }
    button.warn { border-color:#e4bcbc; color:var(--red); background:#fff7f7; }
    .grid { margin-top:14px; display:grid; grid-template-columns:1fr 1fr; gap:12px; }
    .list { height:560px; overflow:auto; }
    .mail-row { border-bottom:1px solid var(--line); padding:10px 6px; cursor:pointer; }
    .mail-row:hover { background:#fff4da; }
    .mail-row.active { background:#fff0cf; }
    .mail-subj { font-weight:700; }
    .mail-meta { color:var(--muted); font-size:12px; margin-top:2px; display:flex; gap:8px; flex-wrap:wrap; }
    .msg { min-height:360px; white-space:pre-wrap; word-break:break-word; background:white; border:1px solid var(--line); border-radius:10px; padding:10px; }
    .muted { color:var(--muted); }
    @media (max-width: 980px) { .grid { grid-template-columns:1fr; } .list { height:320px; } }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <div><h1 class="title">Sisu Inbox</h1><p class="sub">Short-term receive tray. Alias-first triage.</p></div>
      <div class="chips"><span id="chip-conn" class="chip">Connecting...</span><span id="chip-tls" class="chip">Security...</span><span class="chip">No outbound email</span></div>
    </div>
    <div class="nav" style="margin-top:10px"><a class="active" href="/app/inbox">Inbox</a><a href="/app/chat">Chat</a></div>
    <div class="account card">
      <div class="muted">Your Sisumail address</div>
      <select id="addr-switch" class="addr-switch"></select>
    </div>
    <div class="card" style="margin-top:12px">
      <div class="muted" style="margin-bottom:6px">Alias buckets</div>
      <div class="note" style="margin-bottom:8px">Each alias is a separate lane. Pick one to focus this tray.</div>
      <div id="alias-list" class="aliases"></div>
    </div>
    <div class="grid">
      <div class="card"><div id="mail-list" class="list"></div></div>
      <div class="card"><div class="toolbar" style="margin-bottom:8px"><button id="act-delete" class="warn">Delete From Device</button></div><div id="msg-view" class="msg muted">Pick a message.</div></div>
    </div>
  </div>
  <script>
    const APP_SESSION_TOKEN = '__APP_SESSION_TOKEN__';
    const PROFILE_KEY = 'sisu_selected_profile';
    let allMail = [], currentID = '', aliasFilter = 'all', selectedProfile = localStorage.getItem(PROFILE_KEY) || '', currentUser = 'user', profileItems = [];
    const mailList = document.getElementById('mail-list'), msgView = document.getElementById('msg-view');
    const chipConn = document.getElementById('chip-conn'), chipTLS = document.getElementById('chip-tls'), addrSwitch = document.getElementById('addr-switch');
    const esc = (s) => String(s || '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
    function withProfile(path) {
      if (!selectedProfile) return path;
      const sep = path.includes('?') ? '&' : '?';
      return path + sep + 'profile=' + encodeURIComponent(selectedProfile);
    }
    async function api(path, opts={}) {
      const o = { ...opts, headers: { ...(opts.headers || {}), 'X-Sisu-App-Token': APP_SESSION_TOKEN } };
      const r = await fetch(withProfile(path), o);
      if (!r.ok) throw new Error(path + ' -> ' + r.status);
      return r;
    }
    function renderAliases() {
      const box = document.getElementById('alias-list');
      const counts = { all: allMail.length };
      for (const m of allMail) {
        const a = (m.alias || 'inbox').toLowerCase();
        counts[a] = (counts[a] || 0) + 1;
      }
      const keys = Object.keys(counts).sort((a,b) => a==='all' ? -1 : b==='all' ? 1 : a.localeCompare(b));
      box.innerHTML = keys.map(k => '<button class="alias-btn ' + (aliasFilter===k?'active':'') + '" data-a="' + esc(k) + '">' + esc(k) + ' (' + counts[k] + ')</button>').join('');
      for (const b of box.querySelectorAll('.alias-btn')) b.addEventListener('click', () => { aliasFilter = b.getAttribute('data-a') || 'all'; renderAliases(); renderList(); renderAddressSwitch(); });
    }
    function renderAddressSwitch() {
      const local = aliasFilter === 'all' ? '*' : aliasFilter;
      const currentValue = selectedProfile || 'default';
      addrSwitch.innerHTML = profileItems.map(it => {
        const p = String((it && it.profile) || 'default');
        const u = String((it && it.user) || 'user');
        const label = local + '@' + u + '.sisumail.fi';
        return '<option value="' + esc(p) + '">' + esc(label) + '</option>';
      }).join('');
      addrSwitch.value = currentValue;
    }
    function renderList() {
      const rows = allMail.filter(m => aliasFilter === 'all' || (m.alias || 'inbox').toLowerCase() === aliasFilter).slice(0, 120);
      mailList.innerHTML = rows.map(m => '<div class="mail-row ' + (m.id===currentID ? 'active' : '') + '" data-id="' + m.id + '"><div class="mail-subj">' + esc(m.subject || '(no subject)') + '</div><div class="mail-meta"><span>' + esc(m.from || 'Unknown sender') + '</span><span>@' + esc(m.alias || 'inbox') + '</span></div></div>').join('') || '<div class="muted">No messages in this alias bucket.</div>';
      for (const el of mailList.querySelectorAll('.mail-row')) el.addEventListener('click', () => openMessage(el.getAttribute('data-id')));
    }
    let currentProfile = 'default';
    async function refreshStatus() {
      try { const j = await (await api('/app/v1/status')).json(); currentProfile = (j.profile || 'default'); currentUser = (j.user || 'user'); chipConn.textContent='Connected'; chipConn.className='chip good'; chipTLS.textContent = j.tls_authenticated_ca ? 'Secure (Verified)' : 'Secure (Temporary)'; chipTLS.className = j.tls_authenticated_ca ? 'chip good' : 'chip'; renderAddressSwitch(); } catch { chipConn.textContent = 'Disconnected'; chipConn.className = 'chip'; }
    }
    async function loadProfiles() {
      try {
        const r = await fetch('/app/v1/profiles', { headers: { 'X-Sisu-App-Token': APP_SESSION_TOKEN } });
        if (!r.ok) throw new Error('profiles');
        const j = await r.json();
        const list = Array.isArray(j.profiles) ? j.profiles : [{ profile:'default', user:'', address:'' }];
        profileItems = list;
        const fallback = (j.current || currentProfile || 'default');
        if (!selectedProfile) selectedProfile = fallback;
        const exists = list.some(it => String((it && it.profile) || '') === selectedProfile);
        if (!exists) selectedProfile = fallback;
        localStorage.setItem(PROFILE_KEY, selectedProfile);
        renderAddressSwitch();
      } catch {
        profileItems = [{ profile: 'default', user: currentUser, address: '' }];
        renderAddressSwitch();
      }
    }
    async function onProfileChange() {
      selectedProfile = (addrSwitch.value || '').trim();
      localStorage.setItem(PROFILE_KEY, selectedProfile || 'default');
      currentID = '';
      aliasFilter = 'all';
      msgView.classList.add('muted');
      msgView.textContent = 'Pick a message.';
      await refreshStatus();
      await refreshInbox();
    }
    async function refreshInbox() { try { allMail = await (await api('/app/v1/inbox')).json(); renderAliases(); renderList(); } catch { mailList.innerHTML = '<div class="muted">Inbox unavailable.</div>'; } }
    async function openMessage(id) {
      currentID = id; renderList(); msgView.textContent = 'Loading...';
      try { msgView.classList.remove('muted');
        const j = await (await api('/app/v1/message-view/' + encodeURIComponent(id))).json(); let out = 'From: ' + (j.from || 'Unknown sender') + '\nSubject: ' + (j.subject || '(no subject)') + '\n'; if (j.date) out += 'Date: ' + j.date + '\n'; if (j.alias) out += 'Alias: ' + j.alias + '\n'; msgView.textContent = out + '\n' + (j.body || '(empty message)');
      } catch { msgView.classList.add('muted'); msgView.textContent = 'Could not load message.'; }
    }
    async function deleteCurrent() {
      if (!currentID) return;
      try { await api('/app/v1/message/' + encodeURIComponent(currentID) + '/delete', { method:'POST' }); currentID = ''; msgView.classList.add('muted'); msgView.textContent = 'Deleted.'; await refreshInbox(); } catch { alert('Delete failed.'); }
    }
    document.getElementById('act-delete').addEventListener('click', deleteCurrent);
    document.getElementById('addr-switch').addEventListener('change', onProfileChange);
    refreshStatus(); loadProfiles(); refreshInbox();
  </script>
</body>
</html>`

const localChatAppHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Sisu Chat</title>
  <style>
    :root { --sand:#f7f2e7; --ink:#1f1a17; --muted:#655d56; --line:#d9cfbe; --card:#fff9ef; --mint:#1b7d64; --mint2:#0f5f4b; }
    * { box-sizing:border-box; } body { margin:0; color:var(--ink); font-family:"Avenir Next","Trebuchet MS","Segoe UI",sans-serif; background:radial-gradient(1000px 400px at 20% -10%, #fff9da 0%, transparent 65%),radial-gradient(800px 300px at 85% -5%, #d9f2e8 0%, transparent 60%),var(--sand); }
    .wrap { max-width:980px; margin:0 auto; padding:22px; } .hero { display:flex; justify-content:space-between; gap:16px; align-items:flex-start; flex-wrap:wrap; } .title { margin:0; font-size:34px; } .sub { margin:5px 0 0; color:var(--muted); }
    .chips,.toolbar,.nav { display:flex; gap:8px; flex-wrap:wrap; } .chip,.nav a { background:#f0eadc; border:1px solid var(--line); border-radius:999px; padding:6px 10px; font-size:12px; text-decoration:none; color:inherit; } .nav a.active,.chip.good { background:#e6f7f1; border-color:#b7e3d7; color:#0f5f4b; }
    .card { margin-top:14px; background:var(--card); border:1px solid var(--line); border-radius:14px; padding:14px; box-shadow:0 1px 0 rgba(0,0,0,.03); }
    .identity { margin-top:12px; display:block; }
    .id-switch { font-size:16px; font-weight:700; border:1px solid #b7e3d7; background:#f2fff9; color:#0f5f4b; border-radius:12px; padding:10px 12px; min-width:360px; max-width:100%; }
    input,button,textarea { font:inherit; border:1px solid var(--line); border-radius:10px; padding:8px 10px; background:white; } button { cursor:pointer; } button.primary { background:linear-gradient(180deg,var(--mint),var(--mint2)); color:white; border:none; }
    .chat-log { height:380px; overflow:auto; background:white; border:1px solid var(--line); border-radius:10px; padding:8px; margin-top:8px; } .chat-item { margin-bottom:8px; } .chat-item .who { font-size:12px; color:var(--muted); } .chat-item.out { text-align:right; } .chat-send { display:grid; grid-template-columns:1fr auto; gap:8px; margin-top:8px; } .muted { color:var(--muted); }
    .contacts { margin-top:10px; display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
    .pill { border:1px solid var(--line); border-radius:999px; padding:4px 10px; background:white; cursor:pointer; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero"><div><h1 class="title">Sisu Chat</h1><p class="sub">Optional encrypted coordination channel.</p></div><div class="chips"><span id="chip-conn" class="chip">Connecting...</span><span class="chip">Mail identity stays primary</span></div></div>
    <div class="nav" style="margin-top:10px"><a href="/app/inbox">Inbox</a><a class="active" href="/app/chat">Chat</a></div>
    <div class="identity card">
      <div class="muted">Chat identity</div>
      <select id="id-switch" class="id-switch"></select>
    </div>
    <div class="card">
      <div class="toolbar"><input id="chat-peer" placeholder="username (e.g. alice)" /><button id="chat-load">Load</button><button id="chat-add">Add contact</button><button id="chat-remove">Remove contact</button></div>
      <div id="contact-list" class="contacts muted">No contacts yet. Add one to enable chat.</div>
      <div id="chat-log" class="chat-log muted">No chat loaded.</div>
      <div class="chat-send"><textarea id="chat-msg" rows="2" placeholder="Write a message"></textarea><button id="chat-send" class="primary">Send</button></div>
    </div>
  </div>
  <script>
    const APP_SESSION_TOKEN = '__APP_SESSION_TOKEN__';
    const PROFILE_KEY = 'sisu_selected_profile';
    let currentPeer = '', selectedProfile = localStorage.getItem(PROFILE_KEY) || '', currentUser = 'user', profileItems = [];
    const chatLog = document.getElementById('chat-log'); const esc = (s) => String(s || '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
    const rel = (iso) => { const d = new Date(iso); if (isNaN(d.getTime())) return ''; const sec = Math.floor((Date.now()-d.getTime())/1000); if (sec < 60) return sec + 's ago'; if (sec < 3600) return Math.floor(sec/60) + 'm ago'; if (sec < 86400) return Math.floor(sec/3600) + 'h ago'; return Math.floor(sec/86400) + 'd ago'; };
    function withProfile(path) { if (!selectedProfile) return path; const sep = path.includes('?') ? '&' : '?'; return path + sep + 'profile=' + encodeURIComponent(selectedProfile); }
    async function api(path, opts={}) { const o = { ...opts, headers: { ...(opts.headers || {}), 'X-Sisu-App-Token': APP_SESSION_TOKEN } }; const r = await fetch(withProfile(path), o); if (!r.ok) { let msg = ''; try { msg = (await r.text() || '').trim(); } catch {} throw new Error(path + ' -> ' + r.status + (msg ? ': ' + msg : '')); } return r; }
    let currentProfile = 'default';
    function renderIdentitySwitch() {
      const sw = document.getElementById('id-switch');
      sw.innerHTML = profileItems.map(it => {
        const p = String((it && it.profile) || 'default');
        const u = String((it && it.user) || 'user');
        return '<option value="' + esc(p) + '">' + esc('chat@' + u + '.sisumail.fi') + '</option>';
      }).join('');
      sw.value = selectedProfile || currentProfile || 'default';
    }
    async function refreshStatus() { try { const j = await (await api('/app/v1/status')).json(); currentProfile = (j.profile || 'default'); currentUser = (j.user || 'user'); const c = document.getElementById('chip-conn'); c.textContent = 'Connected'; c.className = 'chip good'; } catch {} }
    async function loadProfiles() {
      try {
        const r = await fetch('/app/v1/profiles', { headers: { 'X-Sisu-App-Token': APP_SESSION_TOKEN } });
        if (!r.ok) throw new Error('profiles');
        const j = await r.json();
        const list = Array.isArray(j.profiles) ? j.profiles : [{ profile:'default', user:'', address:'' }];
        profileItems = list;
        const fallback = (j.current || currentProfile || 'default');
        if (!selectedProfile) selectedProfile = fallback;
        const exists = list.some(it => String((it && it.profile) || '') === selectedProfile);
        if (!exists) selectedProfile = fallback;
        localStorage.setItem(PROFILE_KEY, selectedProfile);
        renderIdentitySwitch();
      } catch {
        profileItems = [{ profile: 'default', user: currentUser, address: '' }];
        renderIdentitySwitch();
      }
    }
    async function onProfileChange() {
      selectedProfile = (document.getElementById('id-switch').value || '').trim();
      localStorage.setItem(PROFILE_KEY, selectedProfile || 'default');
      currentPeer = '';
      document.getElementById('chat-peer').value = '';
      chatLog.classList.add('muted');
      chatLog.textContent = 'No chat loaded.';
      await refreshStatus();
      await refreshContacts();
    }
    async function refreshContacts() {
      const box = document.getElementById('contact-list');
      try {
        const peers = await (await api('/app/v1/chat/contacts')).json();
        if (!Array.isArray(peers) || peers.length === 0) { box.className = 'contacts muted'; box.textContent = 'No contacts yet. Add one to enable chat.'; return; }
        box.className = 'contacts';
        box.innerHTML = peers.map(p => '<button class="pill" data-peer="' + esc(p) + '">' + esc(p) + '</button>').join('');
        for (const b of box.querySelectorAll('.pill')) b.addEventListener('click', async () => { const p = b.getAttribute('data-peer') || ''; document.getElementById('chat-peer').value = p; await loadChat(); });
      } catch { box.className = 'contacts muted'; box.textContent = 'Contacts unavailable.'; }
    }
    async function addContact() {
      const p = document.getElementById('chat-peer').value.trim().toLowerCase();
      if (!p) return;
      try { await api('/app/v1/chat/contacts/add', { method:'POST', headers:{ 'Content-Type':'application/json' }, body: JSON.stringify({ peer: p }) }); await refreshContacts(); } catch { alert('Add contact failed.'); }
    }
    async function removeContact() {
      const p = document.getElementById('chat-peer').value.trim().toLowerCase();
      if (!p) return;
      try { await api('/app/v1/chat/contacts/remove', { method:'POST', headers:{ 'Content-Type':'application/json' }, body: JSON.stringify({ peer: p }) }); if (currentPeer === p) { currentPeer = ''; chatLog.classList.add('muted'); chatLog.textContent = 'Contact removed.'; } await refreshContacts(); } catch { alert('Remove contact failed.'); }
    }
    async function loadChat() {
      const p = document.getElementById('chat-peer').value.trim(); if (!p) return; currentPeer = p;
      try { const rows = await (await api('/app/v1/chat/history?peer=' + encodeURIComponent(p) + '&limit=120')).json(); chatLog.classList.remove('muted'); chatLog.innerHTML = rows.map(r => '<div class="chat-item ' + (r.direction==='out' ? 'out' : '') + '"><div class="who">' + (r.direction==='out' ? 'You' : 'Them') + ' • ' + rel(r.at) + '</div><div>' + esc(r.message) + '</div></div>').join('') || '<div class="muted">No messages yet.</div>'; chatLog.scrollTop = chatLog.scrollHeight; } catch (e) { chatLog.classList.add('muted'); chatLog.textContent = String(e).includes('403') ? 'Peer is not in allowlist. Add contact first.' : 'Chat unavailable.'; }
    }
    async function sendChatNow() {
      const msg = document.getElementById('chat-msg').value.trim(); if (!currentPeer || !msg) return;
      try { await api('/app/v1/chat/send', { method:'POST', headers:{ 'Content-Type':'application/json' }, body: JSON.stringify({ to: currentPeer, message: msg }) }); document.getElementById('chat-msg').value = ''; await loadChat(); } catch (e) { const s = String(e).toLowerCase(); alert(s.includes('403') ? 'Peer not in allowlist. Add contact first.' : (s.includes('409') ? 'This profile is view-only right now. Run sisumail with this profile for live chat send.' : (s.includes('relay chat channel unavailable') ? 'Chat is not enabled on this relay yet. Ask operator to enable chat channels.' : 'Chat send failed.'))); }
    }
    document.getElementById('chat-load').addEventListener('click', loadChat);
    document.getElementById('chat-add').addEventListener('click', addContact);
    document.getElementById('chat-remove').addEventListener('click', removeContact);
    document.getElementById('id-switch').addEventListener('change', onProfileChange);
    document.getElementById('chat-send').addEventListener('click', sendChatNow);
    loadProfiles();
    refreshContacts();
    refreshStatus();
  </script>
</body>
</html>`

func buildHostKeyCallback(insecure bool, knownHostsPath string) (ssh.HostKeyCallback, error) {
	if insecure {
		log.Printf("WARNING: relay host key verification disabled (-insecure-host-key)")
		return ssh.InsecureIgnoreHostKey(), nil
	}
	p := strings.TrimSpace(knownHostsPath)
	if p == "" {
		return nil, fmt.Errorf("known_hosts path is empty; set -known-hosts or use -insecure-host-key for dev")
	}
	if _, err := os.Stat(p); err != nil {
		return nil, fmt.Errorf("known_hosts not found at %s", p)
	}
	cb, err := knownhosts.New(p)
	if err != nil {
		return nil, err
	}
	return cb, nil
}

type configField struct {
	FlagName string
	Set      func(string) error
}

type coreConfigValues struct {
	Profile           string
	Relay             string
	User              string
	Zone              string
	Key               string
	KnownHosts        string
	InsecureHostKey   bool
	SMTPListen        string
	TLSPolicy         string
	ACMEDNS01         bool
	ACMEViaRelay      bool
	Shell             bool
	Maildir           string
	ChatDir           string
	ChatContacts      string
	KnownKeys         string
	AliasPolicyPath   string
	ActiveProfilePath string
}

func visitedFlags() map[string]bool {
	out := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		out[strings.TrimSpace(f.Name)] = true
	})
	return out
}

type profileDefaults struct {
	ConfigPath        string
	MaildirRoot       string
	ChatDir           string
	ChatContactsPath  string
	KnownKeysPath     string
	AliasPolicyPath   string
	APITokenPath      string
	ActiveProfilePath string
	KeyPath           string
}

func detectProfileFromArgs(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := strings.TrimSpace(args[i])
		switch {
		case a == "-profile" || a == "--profile":
			if i+1 < len(args) {
				return normalizeProfileName(args[i+1]), true
			}
		case strings.HasPrefix(a, "-profile="):
			_, v, _ := strings.Cut(a, "=")
			return normalizeProfileName(v), true
		case strings.HasPrefix(a, "--profile="):
			_, v, _ := strings.Cut(a, "=")
			return normalizeProfileName(v), true
		}
	}
	return "", false
}

func normalizeProfileName(raw string) string {
	p := strings.ToLower(strings.TrimSpace(raw))
	if p == "" {
		return "default"
	}
	var b strings.Builder
	for _, r := range p {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	out := strings.Trim(b.String(), "-_")
	if out == "" {
		return "default"
	}
	return out
}

func defaultsForProfile(home, profile string) profileDefaults {
	profile = normalizeProfileName(profile)
	baseCfg := filepath.Join(home, ".config", "sisumail")
	baseData := filepath.Join(home, ".local", "share", "sisumail")
	baseState := filepath.Join(home, ".local", "state", "sisumail")
	key := filepath.Join(home, ".ssh", "id_ed25519")
	if profile == "default" {
		return profileDefaults{
			ConfigPath:        filepath.Join(baseCfg, "config.env"),
			MaildirRoot:       filepath.Join(baseData, "mail"),
			ChatDir:           filepath.Join(baseState, "chat"),
			ChatContactsPath:  filepath.Join(baseCfg, "chat_contacts.json"),
			KnownKeysPath:     filepath.Join(baseCfg, "known_peer_keys"),
			AliasPolicyPath:   filepath.Join(baseCfg, "alias_policy.json"),
			APITokenPath:      filepath.Join(baseCfg, "api-token"),
			ActiveProfilePath: filepath.Join(baseCfg, "active_profile"),
			KeyPath:           key,
		}
	}
	pcfg := filepath.Join(baseCfg, "profiles", profile)
	pdata := filepath.Join(baseData, "profiles", profile)
	pstate := filepath.Join(baseState, "profiles", profile)
	return profileDefaults{
		ConfigPath:        filepath.Join(pcfg, "config.env"),
		MaildirRoot:       filepath.Join(pdata, "mail"),
		ChatDir:           filepath.Join(pstate, "chat"),
		ChatContactsPath:  filepath.Join(pcfg, "chat_contacts.json"),
		KnownKeysPath:     filepath.Join(pcfg, "known_peer_keys"),
		AliasPolicyPath:   filepath.Join(pcfg, "alias_policy.json"),
		APITokenPath:      filepath.Join(pcfg, "api-token"),
		ActiveProfilePath: filepath.Join(baseCfg, "active_profile"),
		KeyPath:           key,
	}
}

func readActiveProfile(path string) (string, error) {
	p := strings.TrimSpace(path)
	if p == "" {
		return "", nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return normalizeProfileName(string(b)), nil
}

func writeActiveProfile(path, profile string) error {
	p := strings.TrimSpace(path)
	if p == "" {
		return nil
	}
	profile = normalizeProfileName(profile)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(profile+"\n"), 0600)
}

func listProfiles(home, current string) []string {
	current = normalizeProfileName(current)
	seen := map[string]bool{"default": true}
	out := []string{"default"}
	root := filepath.Join(home, ".config", "sisumail", "profiles")
	entries, err := os.ReadDir(root)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			n := normalizeProfileName(e.Name())
			if n == "" || seen[n] {
				continue
			}
			seen[n] = true
			out = append(out, n)
		}
	}
	if current != "" && !seen[current] {
		out = append(out, current)
	}
	return out
}

func profileUser(home, profile string) string {
	p := normalizeProfileName(profile)
	if p == "default" {
		cfg, err := readConfigFile(filepath.Join(home, ".config", "sisumail", "config.env"))
		if err != nil {
			return ""
		}
		return strings.TrimSpace(cfg["user"])
	}
	cfg, err := readConfigFile(filepath.Join(home, ".config", "sisumail", "profiles", p, "config.env"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cfg["user"])
}

func setString(dst *string) func(string) error {
	return func(v string) error {
		*dst = strings.TrimSpace(v)
		return nil
	}
}

func setBool(dst *bool) func(string) error {
	return func(v string) error {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return err
		}
		*dst = b
		return nil
	}
}

func applyConfigOverrides(path string, explicit map[string]bool, fields map[string]configField) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	values, err := readConfigFile(path)
	if err != nil {
		return err
	}
	for key, raw := range values {
		field, ok := fields[key]
		if !ok {
			continue
		}
		if explicit[field.FlagName] {
			continue
		}
		if err := field.Set(raw); err != nil {
			return fmt.Errorf("parse %s: %w", key, err)
		}
	}
	return nil
}

func readConfigFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	defer f.Close()

	out := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		out[k] = strings.TrimSpace(v)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func writeCoreConfig(path string, cfg coreConfigValues) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("empty config path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	content := strings.Join([]string{
		"# sisumail core defaults",
		"profile=" + cfg.Profile,
		"relay=" + cfg.Relay,
		"user=" + cfg.User,
		"zone=" + cfg.Zone,
		"key=" + cfg.Key,
		"known-hosts=" + cfg.KnownHosts,
		"insecure-host-key=" + strconv.FormatBool(cfg.InsecureHostKey),
		"smtp-listen=" + cfg.SMTPListen,
		"tls-policy=" + cfg.TLSPolicy,
		"acme-dns01=" + strconv.FormatBool(cfg.ACMEDNS01),
		"acme-via-relay=" + strconv.FormatBool(cfg.ACMEViaRelay),
		"shell=" + strconv.FormatBool(cfg.Shell),
		"maildir=" + cfg.Maildir,
		"chat-dir=" + cfg.ChatDir,
		"chat-contacts-path=" + cfg.ChatContacts,
		"known-keys=" + cfg.KnownKeys,
		"alias-policy-path=" + cfg.AliasPolicyPath,
		"active-profile-path=" + cfg.ActiveProfilePath,
		"",
	}, "\n")
	return os.WriteFile(path, []byte(content), 0600)
}

func handleSpoolChannel(ch ssh.NewChannel, sshPrivKey string, store *maildir.Store, aliases *aliasPolicyStore, replay *spoolReplayGuard) {
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
	if replay != nil && replay.SeenOrMark(h.MessageID, time.Now()) {
		log.Printf("spool-delivery: dropped replay msg=%s", h.MessageID)
		_ = proto.WriteSpoolAck(channel, h.MessageID)
		return
	}

	// Decrypt ciphertext stream (bounded), persist locally, and ACK.
	lr := io.LimitReader(br, h.SizeBytes)
	var plain bytes.Buffer
	if err := tier2.StreamDecrypt(&plain, lr, sshPrivKey); err != nil {
		log.Printf("spool-delivery: decrypt failed msg=%s err=%v", h.MessageID, err)
		return
	}

	var alias string
	if m, err := mail.ReadMessage(bytes.NewReader(plain.Bytes())); err == nil {
		alias = aliasFromMessageHeaders(m.Header)
	}
	if alias != "" && aliases != nil && aliases.IsBlocked(alias) {
		log.Printf("spool-delivery: dropped blocked alias=%s msg=%s", alias, h.MessageID)
		_ = proto.WriteSpoolAck(channel, h.MessageID)
		return
	}

	headers := map[string]string{
		"X-Sisumail-Tier":             "tier2",
		"X-Sisumail-Spool-Message-ID": h.MessageID,
		"X-Sisumail-Spool-Size":       fmt.Sprintf("%d", h.SizeBytes),
	}
	if alias != "" {
		headers["X-Sisumail-Alias"] = alias
	}
	msg := injectSisumailHeaders(plain.Bytes(), headers)

	id, err := store.Deliver(bytes.NewReader(msg), "tier2")
	if err != nil {
		log.Printf("spool-delivery: local store failed msg=%s err=%v", h.MessageID, err)
		return
	}
	log.Printf("spool-delivery: stored msg=%s local_id=%s", h.MessageID, id)

	_ = proto.WriteSpoolAck(channel, h.MessageID)
}

func handleChatDeliveryChannel(ch ssh.NewChannel, sshPrivKey string, chats *chatlog.Store, contacts *chatContactsStore) {
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
	if err := ensurePeerAllowed(contacts, h.From); err != nil {
		log.Printf("chat-delivery: dropped from=%s reason=%v", h.From, err)
		_ = proto.WriteChatAck(channel, h.MessageID)
		return
	}
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
		return normalizeChatSendError(err)
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

func runChatREPL(client *ssh.Client, chats *chatlog.Store, known *knownkeys.Store, contacts *chatContactsStore, peer string) error {
	peer = strings.TrimSpace(peer)
	if peer == "" {
		return fmt.Errorf("empty peer")
	}
	if err := ensurePeerAllowed(contacts, peer); err != nil {
		return err
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
			_ = printChatHistory(chats, contacts, peer, 20)
			continue
		}

		if err := ensurePeerAllowed(contacts, peer); err != nil {
			fmt.Printf("chat blocked: %v\n", err)
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

func runCommandShell(username string, store *maildir.Store, client *ssh.Client, chats *chatlog.Store, known *knownkeys.Store, contacts *chatContactsStore) error {
	in := bufio.NewReader(os.Stdin)
	fmt.Printf("Sisumail Shell (%s)\n", username)
	fmt.Println("Sisumail is receive-only mail; chat is optional coordination.")
	fmt.Println("Type ¤help for commands. Quick chat note: allow peer first, then ¤<user> <message>")
	for {
		fmt.Print("¤ ")
		line, err := in.ReadString('\n')
		if err != nil {
			return err
		}
		kind, a, b := parseShellDirective(line)
		switch kind {
		case "noop":
			continue
		case "quit":
			return nil
		case "help":
			fmt.Println("Commands:")
			fmt.Println("¤help")
			fmt.Println("¤whoami")
			fmt.Println("¤inbox")
			fmt.Println("¤read <id>")
			fmt.Println("¤history <user>")
			fmt.Println("¤quit")
			fmt.Println("Quick chat note: ¤<user> <message>")
		case "whoami":
			fmt.Printf("user=%s relay=connected\n", username)
		case "inbox":
			if store == nil {
				fmt.Println("inbox unavailable")
				continue
			}
			if err := printInbox(store); err != nil {
				fmt.Printf("inbox failed: %v\n", err)
			}
		case "read":
			if strings.TrimSpace(a) == "" {
				fmt.Println("usage: ¤read <id>")
				continue
			}
			if store == nil {
				fmt.Println("mail store unavailable")
				continue
			}
			if err := printMessage(store, a); err != nil {
				fmt.Printf("read failed: %v\n", err)
			}
		case "history":
			if strings.TrimSpace(a) == "" {
				fmt.Println("usage: ¤history <user>")
				continue
			}
			if chats == nil {
				fmt.Println("chat history unavailable")
				continue
			}
			if err := printChatHistory(chats, contacts, a, 30); err != nil {
				fmt.Printf("history failed: %v\n", err)
			}
		case "send":
			peer := strings.TrimSpace(a)
			msg := strings.TrimSpace(b)
			if peer == "" || msg == "" {
				fmt.Println("usage: ¤<user> <message>")
				continue
			}
			if client == nil {
				fmt.Println("chat unavailable (no relay connection)")
				continue
			}
			if err := ensurePeerAllowed(contacts, peer); err != nil {
				fmt.Printf("chat blocked: %v\n", err)
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
		default:
			fmt.Println("unknown command. type ¤help")
		}
	}
}

func parseShellDirective(line string) (kind string, arg1 string, arg2 string) {
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
	case "inbox", "i":
		return "inbox", "", ""
	case "read", "r":
		if len(parts) < 2 {
			return "read", "", ""
		}
		return "read", parts[1], ""
	case "history":
		if len(parts) < 2 {
			return "history", "", ""
		}
		return "history", parts[1], ""
	default:
		if len(parts) < 2 {
			return "send", cmd, ""
		}
		msg := strings.TrimSpace(strings.TrimPrefix(s, parts[0]))
		return "send", cmd, msg
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
	store   *maildir.Store
	bridge  *deliveryMetaBridge
	aliases *aliasPolicyStore
}

func (b *localBackend) NewSession(conn *smtp.Conn) (smtp.Session, error) {
	_, isTLS := conn.TLSConnectionState()
	var meta *proto.SMTPDeliveryMeta
	if b != nil && b.bridge != nil && conn != nil && conn.Conn() != nil {
		if m, ok := b.bridge.Take(conn.Conn().RemoteAddr().String()); ok {
			meta = &m
		}
	}
	return &localSession{isTLS: isTLS, store: b.store, senderMeta: meta, aliases: b.aliases}, nil
}

type localSession struct {
	isTLS      bool
	store      *maildir.Store
	senderMeta *proto.SMTPDeliveryMeta
	aliases    *aliasPolicyStore
	rcptAlias  string
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
	alias := aliasFromAddress(to)
	if alias == "" {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 1, 1},
			Message:      "invalid recipient",
		}
	}
	if s.aliases != nil && s.aliases.IsBlocked(alias) {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 1, 1},
			// Keep response uniform to avoid alias enumeration by probing.
			Message: "invalid recipient",
		}
	}
	s.rcptAlias = alias
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
	if strings.TrimSpace(s.rcptAlias) != "" {
		headers["X-Sisumail-Alias"] = strings.TrimSpace(s.rcptAlias)
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
func (s *localSession) Reset()        { s.rcptAlias = "" }
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
	sort.Strings(lines) // stable output; keeps diffs/test fixtures sane

	sepCRLF := []byte("\r\n\r\n")
	sepLF := []byte("\n\n")

	i := bytes.Index(msg, sepCRLF)
	if i >= 0 {
		block := strings.Join(lines, "\r\n")
		out := make([]byte, 0, len(msg)+len(block)+2)
		out = append(out, msg[:i]...)
		out = append(out, []byte("\r\n"+block)...)
		out = append(out, msg[i:]...)
		return out
	}

	i = bytes.Index(msg, sepLF)
	if i >= 0 {
		block := strings.Join(lines, "\n")
		out := make([]byte, 0, len(msg)+len(block)+1)
		out = append(out, msg[:i]...)
		out = append(out, []byte("\n"+block)...)
		out = append(out, msg[i:]...)
		return out
	}

	// No obvious header/body split; just prefix a header block.
	block := strings.Join(lines, "\r\n")
	return append([]byte(block+"\r\n\r\n"), msg...)
}

type spoolReplayGuard struct {
	mu      sync.Mutex
	ttl     time.Duration
	maxSize int
	seen    map[string]time.Time
}

func newSpoolReplayGuard(maxSize int, ttl time.Duration) *spoolReplayGuard {
	if maxSize <= 0 {
		maxSize = 10000
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &spoolReplayGuard{
		ttl:     ttl,
		maxSize: maxSize,
		seen:    make(map[string]time.Time, maxSize),
	}
}

func (g *spoolReplayGuard) SeenOrMark(messageID string, now time.Time) bool {
	if g == nil {
		return false
	}
	id := strings.TrimSpace(messageID)
	if id == "" {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if ts, ok := g.seen[id]; ok && now.Sub(ts) <= g.ttl {
		return true
	}
	g.seen[id] = now
	// Prune old entries and keep a bounded footprint.
	if len(g.seen) > g.maxSize {
		cutoff := now.Add(-g.ttl)
		for k, ts := range g.seen {
			if ts.Before(cutoff) {
				delete(g.seen, k)
			}
		}
		for len(g.seen) > g.maxSize {
			for k := range g.seen {
				delete(g.seen, k)
				break
			}
		}
	}
	return false
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

func printChatHistory(chats *chatlog.Store, contacts *chatContactsStore, peer string, limit int) error {
	if err := ensurePeerAllowed(contacts, peer); err != nil {
		return err
	}
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
	Alias   string
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
	sum.Alias = aliasFromMessageHeaders(m.Header)
	sum.Trust = trustSummary(tier, m.Header)
	return sum
}

func runInboxTUI(store *maildir.Store, client *ssh.Client, chats *chatlog.Store, known *knownkeys.Store, contacts *chatContactsStore) error {
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
			_ = printChatHistory(chats, contacts, peer, 30)
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
			if err := ensurePeerAllowed(contacts, peer); err != nil {
				fmt.Printf("chat blocked: %v\n", err)
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
