package relay

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sisumail/sisumail/internal/proto"
)

type Tier1Proxy struct {
	ListenAddr string
	Listener   net.Listener // optional (tests)

	// DevRouteUser forces all inbound connections to this user (local testing).
	// In production, routing is by dest IPv6.
	DevRouteUser string

	Registry    *SessionRegistry
	ResolveUser func(destIP net.IP) (username string, ok bool)

	// FastFail is the max time we allow between accept and abort when the recipient is offline.
	// Keep this small so MTAs are more likely to try the next MX promptly.
	FastFail time.Duration

	// Hard limits for Tier 1 ingress.
	MaxConnsPerUser   int
	MaxConnsPerSource int

	// Channel open timeout prevents hanging goroutines during SSH channel setup.
	ChannelOpenTimeout time.Duration

	// IdleTimeout bounds stalled bidirectional pipes.
	IdleTimeout time.Duration

	// MaxConnDuration bounds total lifetime of one Tier 1 ingress connection.
	MaxConnDuration time.Duration

	// MaxBytesPerConn bounds total proxied bytes (both directions combined) per connection.
	MaxBytesPerConn int64

	// SMTP prelude filtering (before STARTTLS).
	// Tier 1 cannot inspect TLS payloads; these limits exist to fail fast on obvious abuse
	// and enforce "no MAIL/RCPT/DATA before STARTTLS" to avoid plaintext envelope leakage.
	PreludeTimeout     time.Duration
	PreludeMaxBytes    int64
	PreludeMaxLines    int
	PreludeMaxLineBytes int

	// Observer receives proxy lifecycle/events for metrics.
	Observer Tier1Observer

	mu             sync.Mutex
	activeByUser   map[string]int
	activeBySource map[string]int
}

type Tier1Observer interface {
	OnListening(addr string)
	OnAccepted()
	OnClosed()
	OnRejected(reason string)
	OnChannelOpenTimeout()
	OnChannelOpenError()
	OnPrefaceError()
}

func (p *Tier1Proxy) Run(ctx context.Context) error {
	if p.Registry == nil {
		return fmt.Errorf("missing registry")
	}
	if p.FastFail == 0 {
		p.FastFail = 200 * time.Millisecond
	}
	if p.MaxConnsPerUser <= 0 {
		p.MaxConnsPerUser = 10
	}
	if p.MaxConnsPerSource <= 0 {
		p.MaxConnsPerSource = 20
	}
	if p.ChannelOpenTimeout <= 0 {
		p.ChannelOpenTimeout = 3 * time.Second
	}
	if p.IdleTimeout <= 0 {
		p.IdleTimeout = 2 * time.Minute
	}
	if p.MaxConnDuration <= 0 {
		p.MaxConnDuration = 10 * time.Minute
	}
	if p.MaxBytesPerConn <= 0 {
		p.MaxBytesPerConn = 10 << 20 // 10 MiB
	}
	if p.PreludeTimeout <= 0 {
		p.PreludeTimeout = 8 * time.Second
	}
	if p.PreludeMaxBytes <= 0 {
		p.PreludeMaxBytes = 32 << 10 // 32 KiB
	}
	if p.PreludeMaxLines <= 0 {
		p.PreludeMaxLines = 128
	}
	if p.PreludeMaxLineBytes <= 0 {
		p.PreludeMaxLineBytes = 1200 // slightly above 1000 to allow for CRLF and long params.
	}
	if p.activeByUser == nil {
		p.activeByUser = make(map[string]int)
	}
	if p.activeBySource == nil {
		p.activeBySource = make(map[string]int)
	}

	ln := p.Listener
	var err error
	if ln == nil {
		// Production uses IPv6 AnyIP for Tier 1 and often runs Tier 2 on IPv4 :25.
		// If we listen on "[::]:25" with the default dual-stack behavior, it can
		// unintentionally grab IPv4 too and conflict with the Tier 2 listener.
		network := "tcp"
		if strings.HasPrefix(strings.TrimSpace(p.ListenAddr), "[") {
			network = "tcp6"
		}
		ln, err = net.Listen(network, p.ListenAddr)
		if err != nil {
			return err
		}
	}
	defer ln.Close()

	log.Printf("tier1 proxy listening on %s", p.ListenAddr)
	if p.Observer != nil {
		p.Observer.OnListening(p.ListenAddr)
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			return err
		}
		go p.handleConn(c)
	}
}

func (p *Tier1Proxy) handleConn(inbound net.Conn) {
	defer inbound.Close()

	ra, _ := inbound.RemoteAddr().(*net.TCPAddr)
	source := "unknown"
	if ra != nil && ra.IP != nil {
		source = ra.IP.String()
	}
	if !p.tryAcquireSource(source) {
		if p.Observer != nil {
			p.Observer.OnRejected("source_cap")
		}
		p.fastFail(inbound)
		return
	}
	defer p.releaseSource(source)

	user := p.DevRouteUser
	if user == "" {
		if p.ResolveUser == nil {
			// Keep this strict to avoid a "silent deliver to wrong user" class of bugs.
			return
		}
		la, ok := inbound.LocalAddr().(*net.TCPAddr)
		if !ok || la.IP == nil {
			return
		}
		u, ok := p.ResolveUser(la.IP)
		if !ok {
			// Unknown dest IP: fail fast.
			if p.Observer != nil {
				p.Observer.OnRejected("unknown_dest")
			}
			p.fastFail(inbound)
			return
		}
		user = u
	}
	if !p.tryAcquireUser(user) {
		if p.Observer != nil {
			p.Observer.OnRejected("user_cap")
		}
		p.fastFail(inbound)
		return
	}
	defer p.releaseUser(user)

	sess, ok := p.Registry.GetSession(user)
	if !ok {
		// Fast fail: abort quickly so MTAs attempt alternate MX.
		if p.Observer != nil {
			p.Observer.OnRejected("no_session")
		}
		p.fastFail(inbound)
		return
	}
	if p.Observer != nil {
		p.Observer.OnAccepted()
		defer p.Observer.OnClosed()
	}

	type openRes struct {
		ch  io.ReadWriteCloser
		err error
	}
	resCh := make(chan openRes, 1)
	go func() {
		ch, _, err := sess.Conn.OpenChannel("smtp-delivery", nil)
		if err != nil {
			resCh <- openRes{err: err}
			return
		}
		resCh <- openRes{ch: ch}
	}()

	var ch io.ReadWriteCloser
	select {
	case res := <-resCh:
		if res.err != nil {
			if p.Observer != nil {
				p.Observer.OnChannelOpenError()
				p.Observer.OnRejected("open_failed")
			}
			return
		}
		ch = res.ch
	case <-time.After(p.ChannelOpenTimeout):
		if p.Observer != nil {
			p.Observer.OnChannelOpenTimeout()
			p.Observer.OnRejected("open_timeout")
		}
		p.fastFail(inbound)
		return
	}

	// Preface is out-of-band metadata for the client; do not modify the SMTP byte stream.
	la, _ := inbound.LocalAddr().(*net.TCPAddr)
	meta := proto.SMTPDeliveryMeta{
		SenderIP:   ra.IP,
		SenderPort: ra.Port,
		DestIP:     la.IP,
		ReceivedAt: time.Now(),
	}
	if err := proto.WriteSMTPDeliveryPreface(ch, meta); err != nil {
		if p.Observer != nil {
			p.Observer.OnPrefaceError()
		}
		_ = ch.Close()
		return
	}

	// Bidirectional copy. When one side closes, close the other.
	stopDeadline := func() {}
	if p.MaxConnDuration > 0 {
		timer := time.AfterFunc(p.MaxConnDuration, func() {
			_ = inbound.Close()
			_ = ch.Close()
		})
		stopDeadline = func() { timer.Stop() }
	}
	defer stopDeadline()

	budget := &byteBudget{limit: p.MaxBytesPerConn}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = copySenderToChannelWithSMTPPrelude(inbound, ch, p.PreludeTimeout, p.PreludeMaxBytes, p.PreludeMaxLines, p.PreludeMaxLineBytes, p.IdleTimeout, budget, p.Observer)
		done <- struct{}{}
	}()
	go func() {
		_, _ = copyWithIdleTimeoutAndBudget(inbound, ch, p.IdleTimeout, budget)
		done <- struct{}{}
	}()
	<-done
	_ = ch.Close()
}

func (p *Tier1Proxy) fastFail(inbound net.Conn) {
	if tc, ok := inbound.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
}

var errSMTPPreludeRejected = errors.New("smtp prelude rejected")

func copySenderToChannelWithSMTPPrelude(sender net.Conn, ch io.Writer, preludeTimeout time.Duration, preludeMaxBytes int64, preludeMaxLines int, preludeMaxLineBytes int, idleTimeout time.Duration, budget *byteBudget, obs Tier1Observer) (int64, error) {
	br := bufio.NewReader(sender)
	var (
		total       int64
		preBytes    int64
		lines       int
		sawStartTLS bool
		switchToRaw bool
		rawSrc      io.Reader = sender
		start       = time.Now()
	)

	write := func(b []byte) error {
		if idleTimeout > 0 {
			if wd, ok := ch.(interface{ SetWriteDeadline(time.Time) error }); ok {
				_ = wd.SetWriteDeadline(time.Now().Add(idleTimeout))
			}
		}
		n, err := ch.Write(b)
		total += int64(n)
		if err != nil {
			return err
		}
		if n != len(b) {
			return io.ErrShortWrite
		}
		if !budget.add(int64(n)) {
			return errConnByteBudgetExceeded
		}
		return nil
	}

	// Parse line-oriented SMTP commands until STARTTLS is requested. After that,
	// the stream becomes binary (TLS handshake), so we switch to raw copy.
	for !sawStartTLS && !switchToRaw {
		if preludeTimeout > 0 && time.Since(start) > preludeTimeout {
			if obs != nil {
				obs.OnRejected("prelude_timeout")
			}
			_ = sender.Close()
			return total, errSMTPPreludeRejected
		}
		if preludeMaxBytes > 0 && preBytes >= preludeMaxBytes {
			if obs != nil {
				obs.OnRejected("prelude_bytes")
			}
			_ = sender.Close()
			return total, errSMTPPreludeRejected
		}
		if preludeMaxLines > 0 && lines >= preludeMaxLines {
			if obs != nil {
				obs.OnRejected("prelude_lines")
			}
			_ = sender.Close()
			return total, errSMTPPreludeRejected
		}
		if idleTimeout > 0 {
			dl := time.Now().Add(idleTimeout)
			if preludeTimeout > 0 {
				remain := preludeTimeout - time.Since(start)
				if remain < 0 {
					remain = 0
				}
				rdl := time.Now().Add(remain)
				if rdl.Before(dl) {
					dl = rdl
				}
			}
			_ = sender.SetReadDeadline(dl)
		}
		line, err := br.ReadSlice('\n')
		if len(line) > 0 {
			preBytes += int64(len(line))
			lines++
			// If the line is too long or not line-oriented at all, stop parsing and go raw.
			// This keeps Tier 1 robust if a client connects with a non-SMTP protocol (tests/dev)
			// or if a sender starts TLS without issuing STARTTLS (misbehaving, but we go blind).
			if preludeMaxLineBytes > 0 && len(line) > preludeMaxLineBytes {
				switchToRaw = true
			}

			// Normalize for parsing only (do not alter forwarded bytes).
			if !switchToRaw {
				s := strings.TrimSpace(strings.TrimRight(string(line), "\r\n"))
				up := strings.ToUpper(s)
				if strings.HasPrefix(up, "MAIL FROM:") || strings.HasPrefix(up, "RCPT TO:") || up == "DATA" || strings.HasPrefix(up, "BDAT ") {
					if obs != nil {
						obs.OnRejected("mail_before_starttls")
					}
					_ = sender.Close()
					return total, errSMTPPreludeRejected
				}
				if up == "STARTTLS" {
					sawStartTLS = true
				}
			}
			if err := write(line); err != nil {
				return total, err
			}
		}
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				// No newline in buffer yet; treat as raw and keep piping.
				switchToRaw = true
				rawSrc = br
				break
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// Sender isn't speaking line-oriented SMTP prelude quickly; go raw.
				switchToRaw = true
				rawSrc = br
				break
			}
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}

	// After STARTTLS request (or when giving up parsing), switch to raw copy.
	if switchToRaw {
		rawSrc = br
	} else if sawStartTLS {
		if n := br.Buffered(); n > 0 {
			buf, _ := br.Peek(n)
			if len(buf) > 0 {
				if err := write(buf); err != nil {
					return total, err
				}
			}
			_, _ = br.Discard(n)
		}
		rawSrc = sender
	}

	n, err := copyWithIdleTimeoutAndBudget(ch, rawSrc, idleTimeout, budget)
	return total + n, err
}

func (p *Tier1Proxy) tryAcquireUser(user string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.activeByUser[user] >= p.MaxConnsPerUser {
		return false
	}
	p.activeByUser[user]++
	return true
}

func (p *Tier1Proxy) releaseUser(user string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := p.activeByUser[user] - 1
	if n <= 0 {
		delete(p.activeByUser, user)
		return
	}
	p.activeByUser[user] = n
}

func (p *Tier1Proxy) tryAcquireSource(source string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.activeBySource[source] >= p.MaxConnsPerSource {
		return false
	}
	p.activeBySource[source]++
	return true
}

func (p *Tier1Proxy) releaseSource(source string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := p.activeBySource[source] - 1
	if n <= 0 {
		delete(p.activeBySource, source)
		return
	}
	p.activeBySource[source] = n
}

func copyWithIdleTimeout(dst io.Writer, src io.Reader, idle time.Duration) (int64, error) {
	return copyWithIdleTimeoutAndBudget(dst, src, idle, nil)
}

var errConnByteBudgetExceeded = errors.New("tier1 connection byte budget exceeded")

type byteBudget struct {
	limit int64
	used  atomic.Int64
}

func (b *byteBudget) add(n int64) bool {
	if b == nil || b.limit <= 0 || n <= 0 {
		return true
	}
	return b.used.Add(n) <= b.limit
}

func copyWithIdleTimeoutAndBudget(dst io.Writer, src io.Reader, idle time.Duration, budget *byteBudget) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64

	for {
		if idle > 0 {
			if rd, ok := src.(interface{ SetReadDeadline(time.Time) error }); ok {
				_ = rd.SetReadDeadline(time.Now().Add(idle))
			}
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			if idle > 0 {
				if wd, ok := dst.(interface{ SetWriteDeadline(time.Time) error }); ok {
					_ = wd.SetWriteDeadline(time.Now().Add(idle))
				}
			}
			nw, ew := dst.Write(buf[:nr])
			total += int64(nw)
			if ew != nil {
				return total, ew
			}
			if nw != nr {
				return total, io.ErrShortWrite
			}
			if !budget.add(int64(nw)) {
				return total, errConnByteBudgetExceeded
			}
		}
		if er != nil {
			if er == io.EOF {
				return total, nil
			}
			return total, er
		}
	}
}
