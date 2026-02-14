package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/sisumail/sisumail/internal/identity"
)

func main() {
	var (
		zone       = flag.String("zone", "v6.sisumail.fi.", "authoritative zone (FQDN, trailing dot recommended)")
		listenUDP  = flag.String("listen-udp", ":53", "UDP listen address")
		listenTCP  = flag.String("listen-tcp", ":53", "TCP listen address")
		dbPath     = flag.String("db", "/var/lib/sisumail/relay.db", "identity sqlite path")
		soaNS      = flag.String("soa-ns", "ns1.sisumail.fi.", "SOA mname (primary nameserver FQDN)")
		soaMbox    = flag.String("soa-mbox", "hostmaster.sisumail.fi.", "SOA rname (mailbox as FQDN)")
		ttl        = flag.Uint("ttl", 300, "answer TTL seconds (AAAA/NS)")
		negTTL     = flag.Uint("neg-ttl", 60, "negative TTL seconds (SOA MINIMUM + NXDOMAIN caching)")
		readTO     = flag.Duration("read-timeout", 2*time.Second, "DNS read timeout")
		writeTO    = flag.Duration("write-timeout", 2*time.Second, "DNS write timeout")
		maxQueries = flag.Int("max-qps-per-source", 200, "best-effort QPS per source IP (0 disables)")
	)
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	z := dns.Fqdn(strings.TrimSpace(*zone))
	if z == "." {
		log.Fatalf("invalid -zone")
	}
	if !strings.HasSuffix(z, ".") {
		log.Fatalf("-zone must be a FQDN")
	}

	store, err := identity.Open(*dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer store.Close()
	if err := store.Init(ctx); err != nil {
		log.Fatalf("init db: %v", err)
	}

	h := &handler{
		Zone:    z,
		Store:   store,
		TTL:     uint32(*ttl),
		NegTTL:  uint32(*negTTL),
		SOANS:   dns.Fqdn(strings.TrimSpace(*soaNS)),
		SOAMbox: dns.Fqdn(strings.TrimSpace(*soaMbox)),
		Limiter: newIPLimiter(*maxQueries, time.Second),
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(z, h.ServeDNS)

	udp := &dns.Server{Addr: *listenUDP, Net: "udp", Handler: mux, ReadTimeout: *readTO, WriteTimeout: *writeTO}
	tcp := &dns.Server{Addr: *listenTCP, Net: "tcp", Handler: mux, ReadTimeout: *readTO, WriteTimeout: *writeTO}

	errCh := make(chan error, 2)
	go func() {
		log.Printf("dns: listening udp=%s zone=%s", *listenUDP, z)
		errCh <- udp.ListenAndServe()
	}()
	go func() {
		log.Printf("dns: listening tcp=%s zone=%s", *listenTCP, z)
		errCh <- tcp.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil {
			log.Printf("dns: server error: %v", err)
		}
	}

	shutdownCtx, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	_ = udp.ShutdownContext(shutdownCtx)
	_ = tcp.ShutdownContext(shutdownCtx)
}

type handler struct {
	Zone    string
	Store   *identity.Store
	TTL     uint32
	NegTTL  uint32
	SOANS   string
	SOAMbox string
	Limiter *ipLimiter
}

func (h *handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	q := dns.Question{}
	if len(r.Question) > 0 {
		q = r.Question[0]
	}

	if h.Limiter != nil {
		ra := remoteHost(w.RemoteAddr())
		if ra != "" && !h.Limiter.Allow(ra) {
			// REFUSED is appropriate for policy-based refusal.
			m.Rcode = dns.RcodeRefused
			_ = w.WriteMsg(m)
			return
		}
	}

	name := dns.Fqdn(strings.ToLower(strings.TrimSpace(q.Name)))
	if !dns.IsSubDomain(h.Zone, name) {
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}

	switch q.Qtype {
	case dns.TypeSOA:
		m.Answer = append(m.Answer, h.soaRR())
	case dns.TypeNS:
		m.Answer = append(m.Answer, h.nsRR())
	case dns.TypeAAAA:
		// Expect: <user>.<zone>
		user := strings.TrimSuffix(name, h.Zone)
		user = strings.TrimSuffix(user, ".")
		u, err := identity.CanonicalUsername(user)
		if err != nil || identityIsReserved(u) {
			h.nxdomain(m)
			_ = w.WriteMsg(m)
			return
		}
		rec, err := h.Store.GetByUsername(context.Background(), u)
		if err != nil || rec == nil || rec.IPv6 == nil || rec.IPv6.To16() == nil {
			h.nxdomain(m)
			_ = w.WriteMsg(m)
			return
		}
		m.Answer = append(m.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: h.TTL},
			AAAA: rec.IPv6,
		})
	default:
		// For unknown types in-zone, reply NXDOMAIN with SOA for negative caching.
		h.nxdomain(m)
	}

	_ = w.WriteMsg(m)
}

func (h *handler) nsRR() dns.RR {
	ns := dns.Fqdn(h.SOANS)
	if ns == "." {
		ns = "ns1.invalid."
	}
	return &dns.NS{
		Hdr: dns.RR_Header{Name: h.Zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: h.TTL},
		Ns:  ns,
	}
}

func (h *handler) soaRR() dns.RR {
	mname := dns.Fqdn(h.SOANS)
	if mname == "." {
		mname = "ns1.invalid."
	}
	rname := dns.Fqdn(h.SOAMbox)
	if rname == "." {
		rname = "hostmaster.invalid."
	}
	serial := uint32(time.Now().UTC().Unix())
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: h.Zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: uint32(h.NegTTL)},
		Ns:      mname,
		Mbox:    rname,
		Serial:  serial,
		Refresh: 3600,
		Retry:   900,
		Expire:  1209600,
		Minttl:  uint32(h.NegTTL),
	}
}

func (h *handler) nxdomain(m *dns.Msg) {
	m.Rcode = dns.RcodeNameError
	m.Ns = append(m.Ns, h.soaRR())
}

func remoteHost(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil && host != "" {
		return host
	}
	return addr.String()
}

// Keep this aligned with relay's reserved list intent, but scoped to DNS answers.
func identityIsReserved(u string) bool {
	switch strings.ToLower(strings.TrimSpace(u)) {
	case "admin", "postmaster", "abuse", "hostmaster", "webmaster", "mailer-daemon",
		"root", "security", "support", "info", "contact", "noreply", "no-reply",
		"www", "ftp", "mail", "smtp", "imap", "pop", "ns1", "ns2", "mx", "mta-sts",
		"spool", "v6":
		return true
	default:
		return false
	}
}
