package relay

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sisumail/sisumail/internal/proto"
	"golang.org/x/crypto/ssh"
)

type fakeConn struct {
	open func(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error)
}

func (c *fakeConn) OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	return c.open(name, data)
}

type fakeChannel struct {
	net.Conn
	stderr io.ReadWriter
}

func (c *fakeChannel) CloseWrite() error { return nil }
func (c *fakeChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return false, nil
}
func (c *fakeChannel) Stderr() io.ReadWriter {
	if c.stderr == nil {
		c.stderr = bytes.NewBuffer(nil)
	}
	return c.stderr
}

func TestTier1FastFailWhenOffline(t *testing.T) {
	reg := NewSessionRegistry()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	p := &Tier1Proxy{
		Listener:     ln,
		DevRouteUser: "niklas",
		Registry:     reg,
		FastFail:     200 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = p.Run(ctx) }()

	addr := ln.Addr().String()

	// Dial and expect immediate close (RST/FIN) with no session.
	start := time.Now()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	n, rerr := c.Read(buf)
	if n != 0 || rerr == nil {
		t.Fatalf("expected connection closed quickly, got n=%d err=%v", n, rerr)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("close took too long: %s", time.Since(start))
	}
}

func TestTier1PipesBytesAndPreface(t *testing.T) {
	reg := NewSessionRegistry()

	// Create a fake ssh channel backed by net.Pipe.
	serverSide, clientSide := net.Pipe()
	ch := &fakeChannel{Conn: serverSide}

	reqCh := make(chan *ssh.Request)
	close(reqCh)

	reg.SetSession("niklas", &Session{
		Username: "niklas",
		Conn: &fakeConn{open: func(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
			return ch, reqCh, nil
		}},
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	p := &Tier1Proxy{
		Listener:     ln,
		DevRouteUser: "niklas",
		Registry:     reg,
		FastFail:     200 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Run(ctx) }()

	in, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer in.Close()

	// From sender -> relay -> ssh channel.
	if _, err := in.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}

	br := bufio.NewReader(clientSide)
	meta, err := proto.ReadSMTPDeliveryPreface(br)
	if err != nil {
		t.Fatalf("read preface: %v", err)
	}
	if meta.SenderPort == 0 {
		t.Fatalf("expected sender port")
	}

	msg := make([]byte, 5)
	if _, err := io.ReadFull(br, msg); err != nil {
		t.Fatalf("read msg: %v", err)
	}
	if string(msg) != "hello" {
		t.Fatalf("msg: got %q", string(msg))
	}

	// From ssh channel -> relay -> sender.
	if _, err := clientSide.Write([]byte("world")); err != nil {
		t.Fatalf("write back: %v", err)
	}
	rb := make([]byte, 5)
	_ = in.SetReadDeadline(time.Now().Add(1 * time.Second))
	if _, err := io.ReadFull(in, rb); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(rb) != "world" {
		t.Fatalf("back: got %q", string(rb))
	}
}

func TestTier1EnforcesPerUserConnCap(t *testing.T) {
	reg := NewSessionRegistry()
	serverSide, _ := net.Pipe()
	ch := &fakeChannel{Conn: serverSide}
	reqCh := make(chan *ssh.Request)
	close(reqCh)
	reg.SetSession("niklas", &Session{
		Username: "niklas",
		Conn: &fakeConn{open: func(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
			return ch, reqCh, nil
		}},
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	p := &Tier1Proxy{
		Listener:          ln,
		DevRouteUser:      "niklas",
		Registry:          reg,
		MaxConnsPerUser:   1,
		MaxConnsPerSource: 10,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Run(ctx) }()

	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial first: %v", err)
	}
	defer c1.Close()

	time.Sleep(80 * time.Millisecond)

	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial second: %v", err)
	}
	defer c2.Close()

	assertClosedQuickly(t, c2, 500*time.Millisecond)
}

func TestTier1EnforcesPerSourceConnCap(t *testing.T) {
	reg := NewSessionRegistry()
	serverSide, _ := net.Pipe()
	ch := &fakeChannel{Conn: serverSide}
	reqCh := make(chan *ssh.Request)
	close(reqCh)
	reg.SetSession("niklas", &Session{
		Username: "niklas",
		Conn: &fakeConn{open: func(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
			return ch, reqCh, nil
		}},
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	p := &Tier1Proxy{
		Listener:          ln,
		DevRouteUser:      "niklas",
		Registry:          reg,
		MaxConnsPerUser:   10,
		MaxConnsPerSource: 1,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Run(ctx) }()

	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial first: %v", err)
	}
	defer c1.Close()

	time.Sleep(80 * time.Millisecond)

	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial second: %v", err)
	}
	defer c2.Close()

	assertClosedQuickly(t, c2, 500*time.Millisecond)
}

func TestTier1ChannelOpenTimeout(t *testing.T) {
	reg := NewSessionRegistry()
	var opens int32
	reg.SetSession("niklas", &Session{
		Username: "niklas",
		Conn: &fakeConn{open: func(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
			atomic.AddInt32(&opens, 1)
			time.Sleep(250 * time.Millisecond)
			return nil, nil, io.EOF
		}},
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	p := &Tier1Proxy{
		Listener:           ln,
		DevRouteUser:       "niklas",
		Registry:           reg,
		ChannelOpenTimeout: 50 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Run(ctx) }()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	assertClosedQuickly(t, c, 500*time.Millisecond)

	if atomic.LoadInt32(&opens) == 0 {
		t.Fatal("expected OpenChannel attempt")
	}
}

func TestTier1EnforcesMaxConnDuration(t *testing.T) {
	reg := NewSessionRegistry()
	serverSide, _ := net.Pipe()
	ch := &fakeChannel{Conn: serverSide}
	reqCh := make(chan *ssh.Request)
	close(reqCh)
	reg.SetSession("niklas", &Session{
		Username: "niklas",
		Conn: &fakeConn{open: func(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
			return ch, reqCh, nil
		}},
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	p := &Tier1Proxy{
		Listener:          ln,
		DevRouteUser:      "niklas",
		Registry:          reg,
		MaxConnsPerUser:   10,
		MaxConnsPerSource: 10,
		MaxConnDuration:   120 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Run(ctx) }()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	assertClosedQuickly(t, c, 700*time.Millisecond)
}

func TestTier1EnforcesMaxBytesPerConn(t *testing.T) {
	reg := NewSessionRegistry()
	serverSide, clientSide := net.Pipe()
	ch := &fakeChannel{Conn: serverSide}
	reqCh := make(chan *ssh.Request)
	close(reqCh)
	reg.SetSession("niklas", &Session{
		Username: "niklas",
		Conn: &fakeConn{open: func(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
			return ch, reqCh, nil
		}},
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	p := &Tier1Proxy{
		Listener:          ln,
		DevRouteUser:      "niklas",
		Registry:          reg,
		MaxConnsPerUser:   10,
		MaxConnsPerSource: 10,
		MaxBytesPerConn:   1,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Run(ctx) }()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// Consume delivery preface first to reach proxied payload path.
	br := bufio.NewReader(clientSide)
	if _, err := proto.ReadSMTPDeliveryPreface(br); err != nil {
		t.Fatalf("read preface: %v", err)
	}

	if _, err := c.Write([]byte("ab")); err != nil {
		t.Fatalf("write: %v", err)
	}
	assertClosedQuickly(t, c, 700*time.Millisecond)
}

func assertClosedQuickly(t *testing.T, c net.Conn, d time.Duration) {
	t.Helper()

	_ = c.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 1)
	n, err := c.Read(buf)
	if n != 0 || err == nil {
		t.Fatalf("expected quick close, got n=%d err=%v", n, err)
	}
}
