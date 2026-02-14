package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/sisumail/sisumail/internal/identity"
	"github.com/sisumail/sisumail/internal/tier2"
)

func main() {
	var (
		listen                 = flag.String("listen", ":2526", "Tier 2 SMTP listen address (staging default :2526)")
		zone                   = flag.String("zone", "", "root zone name, e.g. sisumail.fi (required)")
		dbPath                 = flag.String("db", "/var/lib/sisumail/relay.db", "identity database path (shared with relay)")
		spoolDir               = flag.String("spool-dir", "/var/spool/sisumail", "Tier 2 ciphertext spool root")
		maxBytes               = flag.Int64("max-bytes", 25<<20, "max message size in bytes (0 = unlimited)")
		certPath               = flag.String("tls-cert", "", "TLS cert PEM for STARTTLS (recommended for real MX)")
		keyPath                = flag.String("tls-key", "", "TLS key PEM for STARTTLS (recommended for real MX)")
		tlsMode                = flag.String("tls-mode", "opportunistic", "TLS mode: disable|opportunistic|required")
		denylistPath           = flag.String("denylist-path", "", "path to source-IP denylist file (IP/CIDR per line)")
		maxConnsPerSource      = flag.Int("max-conns-per-source", 20, "max concurrent SMTP connections per source IP (0 disables)")
		maxMsgsPerSourcePerMin = flag.Int("max-msgs-per-source-per-min", 60, "max accepted messages per source IP per minute (0 disables)")
	)
	flag.Parse()

	if *zone == "" {
		log.Fatalf("missing -zone (e.g. sisumail.fi)")
	}

	mode, err := parseTLSMode(*tlsMode)
	if err != nil {
		log.Fatalf("invalid -tls-mode: %v", err)
	}
	denylist, err := tier2.ParseDenylist(*denylistPath)
	if err != nil {
		log.Fatalf("parse -denylist-path: %v", err)
	}
	guard := tier2.NewSourceGuard(*maxConnsPerSource, *maxMsgsPerSourcePerMin, denylist)

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

	resolver := &identity.DomainKeyResolver{
		Store:   store,
		Zone:    *zone,
		Timeout: 2 * time.Second,
	}

	spool := &tier2.FileSpool{Root: *spoolDir}
	backend := &tier2.Receiver{
		KeyResolver: resolver,
		Spool:       spool,
		Domain:      *zone,
		MaxSize:     *maxBytes,
		RequireTLS:  mode == tlsModeRequired,
		Guard:       guard,
	}

	srv := smtp.NewServer(backend)
	// Force the network family when the operator provides an explicit IP.
	// This matters for the Tier 1 + Tier 2 same-host setup:
	// - Tier 1 uses IPv6 AnyIP on :25
	// - Tier 2 often binds IPv4 only on 0.0.0.0:25
	// If we listen on an IPv4 address but net.Listen selects a dual-stack socket,
	// Tier 1 cannot bind IPv6 :25.
	if host, _, err := net.SplitHostPort(*listen); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			if ip.To4() != nil {
				srv.Network = "tcp4"
			} else {
				srv.Network = "tcp6"
			}
		}
	}
	srv.Addr = *listen
	srv.Domain = fmt.Sprintf("spool.%s", *zone)
	srv.AllowInsecureAuth = false
	srv.EnableSMTPUTF8 = false
	srv.ReadTimeout = 30 * time.Second
	srv.WriteTimeout = 30 * time.Second
	srv.MaxMessageBytes = *maxBytes
	srv.MaxRecipients = 50

	hasCert := *certPath != "" || *keyPath != ""
	if hasCert && (*certPath == "" || *keyPath == "") {
		log.Fatalf("both -tls-cert and -tls-key must be provided")
	}
	if mode == tlsModeRequired && !hasCert {
		log.Fatalf("tls mode 'required' needs -tls-cert and -tls-key")
	}

	if hasCert {
		cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
		if err != nil {
			log.Fatalf("load tls cert: %v", err)
		}
		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		log.Printf("tier2: STARTTLS enabled (mode=%s cert=%s key=%s)", mode, *certPath, *keyPath)
	} else {
		switch mode {
		case tlsModeDisable:
			log.Printf("tier2: STARTTLS disabled (mode=%s)", mode)
		case tlsModeOpportunistic:
			log.Printf("tier2: STARTTLS disabled (no -tls-cert/-tls-key provided, mode=%s)", mode)
		}
	}

	go func() {
		log.Printf("tier2: listening on %s (zone=%s spool=%s denylist_entries=%d conn_cap=%d msg_rate_per_min=%d)",
			*listen, *zone, *spoolDir, len(denylist), *maxConnsPerSource, *maxMsgsPerSourcePerMin)
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("tier2: server error: %v", err)
			cancel()
		}
	}()

	<-ctx.Done()
	_ = srv.Close()
}

type tlsModeKind string

const (
	tlsModeDisable       tlsModeKind = "disable"
	tlsModeOpportunistic tlsModeKind = "opportunistic"
	tlsModeRequired      tlsModeKind = "required"
)

func parseTLSMode(s string) (tlsModeKind, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(tlsModeDisable):
		return tlsModeDisable, nil
	case string(tlsModeOpportunistic):
		return tlsModeOpportunistic, nil
	case string(tlsModeRequired):
		return tlsModeRequired, nil
	default:
		return "", errors.New("expected disable|opportunistic|required")
	}
}
