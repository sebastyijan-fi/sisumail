package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/sisumail/sisumail/internal/identity"
	"github.com/sisumail/sisumail/internal/tier2"
)

func main() {
	var (
		listen   = flag.String("listen", ":2526", "Tier 2 SMTP listen address (staging default :2526)")
		zone     = flag.String("zone", "", "root zone name, e.g. sisumail.fi (required)")
		dbPath   = flag.String("db", "/var/lib/sisumail/relay.db", "identity database path (shared with relay)")
		spoolDir = flag.String("spool-dir", "/var/spool/sisumail", "Tier 2 ciphertext spool root")
		maxBytes = flag.Int64("max-bytes", 25<<20, "max message size in bytes (0 = unlimited)")
		certPath = flag.String("tls-cert", "", "TLS cert PEM for STARTTLS (recommended for real MX)")
		keyPath  = flag.String("tls-key", "", "TLS key PEM for STARTTLS (recommended for real MX)")
	)
	flag.Parse()

	if *zone == "" {
		log.Fatalf("missing -zone (e.g. sisumail.fi)")
	}

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
	}

	srv := smtp.NewServer(backend)
	srv.Addr = *listen
	srv.Domain = fmt.Sprintf("spool.%s", *zone)
	srv.AllowInsecureAuth = false
	srv.EnableSMTPUTF8 = false
	srv.ReadTimeout = 30 * time.Second
	srv.WriteTimeout = 30 * time.Second
	srv.MaxMessageBytes = *maxBytes
	srv.MaxRecipients = 50

	if *certPath != "" && *keyPath != "" {
		cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
		if err != nil {
			log.Fatalf("load tls cert: %v", err)
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		log.Printf("tier2: STARTTLS enabled (cert=%s key=%s)", *certPath, *keyPath)
	} else {
		log.Printf("tier2: STARTTLS disabled (no -tls-cert/-tls-key provided)")
	}

	go func() {
		log.Printf("tier2: listening on %s (zone=%s spool=%s)", *listen, *zone, *spoolDir)
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("tier2: server error: %v", err)
			cancel()
		}
	}()

	<-ctx.Done()
	_ = srv.Close()
}

