package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/sisumail/sisumail/internal/proto"
	"golang.org/x/crypto/ssh"
)

type relayDNS01Presenter struct {
	client *ssh.Client
}

func (p *relayDNS01Presenter) Present(hostname, value string) (func(), error) {
	if p == nil || p.client == nil {
		return nil, fmt.Errorf("relay dns presenter unavailable")
	}
	host := strings.TrimSpace(hostname)
	val := strings.TrimSpace(value)
	if host == "" || val == "" {
		return nil, fmt.Errorf("invalid acme dns challenge")
	}
	if err := p.exec("PRESENT", host, val); err != nil {
		return nil, err
	}
	return func() {
		_ = p.exec("CLEANUP", host, val)
	}, nil
}

func (p *relayDNS01Presenter) exec(op, host, val string) error {
	ch, reqs, err := p.client.OpenChannel("acme-dns01", nil)
	if err != nil {
		return err
	}
	go ssh.DiscardRequests(reqs)
	defer ch.Close()

	if err := proto.WriteACMEDNS01Request(ch, proto.ACMEDNS01Request{
		Op:       op,
		Hostname: host,
		Value:    val,
	}); err != nil {
		return err
	}
	resp, err := proto.ReadACMEDNS01Response(ch)
	if err != nil {
		return err
	}
	if !resp.OK {
		msg := strings.TrimSpace(resp.Message)
		if msg == "" {
			msg = "acme dns control rejected request"
		}
		return errors.New(msg)
	}
	return nil
}
