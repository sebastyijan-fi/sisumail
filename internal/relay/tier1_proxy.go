package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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

	mu             sync.Mutex
	activeByUser   map[string]int
	activeBySource map[string]int
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
	if p.activeByUser == nil {
		p.activeByUser = make(map[string]int)
	}
	if p.activeBySource == nil {
		p.activeBySource = make(map[string]int)
	}

	ln := p.Listener
	var err error
	if ln == nil {
		ln, err = net.Listen("tcp", p.ListenAddr)
		if err != nil {
			return err
		}
	}
	defer ln.Close()

	log.Printf("tier1 proxy listening on %s", p.ListenAddr)

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
			p.fastFail(inbound)
			return
		}
		user = u
	}
	if !p.tryAcquireUser(user) {
		p.fastFail(inbound)
		return
	}
	defer p.releaseUser(user)

	sess, ok := p.Registry.GetSession(user)
	if !ok {
		// Fast fail: abort quickly so MTAs attempt alternate MX.
		p.fastFail(inbound)
		return
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
			return
		}
		ch = res.ch
	case <-time.After(p.ChannelOpenTimeout):
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
		_, _ = copyWithIdleTimeoutAndBudget(ch, inbound, p.IdleTimeout, budget)
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
