package tlsboot

import (
	"crypto/tls"
	"fmt"
	"time"
)

// CertResult is returned by a provider; it includes what we can *truthfully* label.
type CertResult struct {
	Cert tls.Certificate

	// Encrypted is true if we can offer STARTTLS at all (i.e. have a cert to present).
	Encrypted bool

	// AuthenticatedCA indicates the certificate is publicly trusted and valid *locally*.
	// This is not a guarantee that all senders validated it.
	AuthenticatedCA bool

	// Source describes where the cert came from: "acme", "disk", "selfsigned".
	Source string
}

type Provider interface {
	GetCertificate(now time.Time) (CertResult, error)
}

// PragmaticProvider returns the best available certificate and falls back to a self-signed cert.
// StrictProvider fails if no usable certificate is available.
type PragmaticProvider struct {
	Hostnames []string

	// Primary should return an ACME or on-disk certificate when available.
	Primary Provider

	// SelfSignedValidity controls how long bootstrap self-signed certs last.
	SelfSignedValidity time.Duration
}

func (p *PragmaticProvider) GetCertificate(now time.Time) (CertResult, error) {
	if p.Primary != nil {
		if res, err := p.Primary.GetCertificate(now); err == nil && res.Encrypted {
			return res, nil
		}
	}
	cert, err := SelfSigned(p.Hostnames, p.SelfSignedValidity)
	if err != nil {
		return CertResult{}, err
	}
	return CertResult{
		Cert:            cert,
		Encrypted:       true,
		AuthenticatedCA: false,
		Source:          "selfsigned",
	}, nil
}

type StrictProvider struct {
	Primary Provider
}

func (p *StrictProvider) GetCertificate(now time.Time) (CertResult, error) {
	if p.Primary == nil {
		return CertResult{}, fmt.Errorf("no primary cert provider configured")
	}
	res, err := p.Primary.GetCertificate(now)
	if err != nil {
		return CertResult{}, err
	}
	if !res.Encrypted {
		return CertResult{}, fmt.Errorf("no usable certificate")
	}
	return res, nil
}

