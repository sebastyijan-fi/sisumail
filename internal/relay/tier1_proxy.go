package relay

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
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
}

func (p *Tier1Proxy) Run(ctx context.Context) error {
	if p.Registry == nil {
		return fmt.Errorf("missing registry")
	}
	if p.FastFail == 0 {
		p.FastFail = 200 * time.Millisecond
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

	_ = inbound.SetDeadline(time.Now().Add(10 * time.Minute))

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
			if tc, ok := inbound.(*net.TCPConn); ok {
				_ = tc.SetLinger(0)
			}
			return
		}
		user = u
	}

	sess, ok := p.Registry.GetSession(user)
	if !ok {
		// Fast fail: abort quickly so MTAs attempt alternate MX.
		if tc, ok := inbound.(*net.TCPConn); ok {
			// RST on close.
			_ = tc.SetLinger(0)
		}
		return
	}

	ch, _, err := sess.Conn.OpenChannel("smtp-delivery", nil)
	if err != nil {
		return
	}

	// Preface is out-of-band metadata for the client; do not modify the SMTP byte stream.
	ra, _ := inbound.RemoteAddr().(*net.TCPAddr)
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
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(ch, inbound); done <- struct{}{} }()
	go func() { _, _ = io.Copy(inbound, ch); done <- struct{}{} }()
	<-done
	_ = ch.Close()
}
