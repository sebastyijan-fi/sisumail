package tlsboot

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"
)

// DiskProvider loads a certificate/key pair from disk.
// In v1 this is the "primary" source; ACME will later populate these paths.
type DiskProvider struct {
	CertPath string
	KeyPath  string
}

func (p *DiskProvider) GetCertificate(now time.Time) (CertResult, error) {
	if p.CertPath == "" || p.KeyPath == "" {
		return CertResult{}, fmt.Errorf("missing cert/key paths")
	}
	if _, err := os.Stat(p.CertPath); err != nil {
		return CertResult{Encrypted: false, Source: "disk"}, err
	}
	if _, err := os.Stat(p.KeyPath); err != nil {
		return CertResult{Encrypted: false, Source: "disk"}, err
	}

	cert, err := tls.LoadX509KeyPair(p.CertPath, p.KeyPath)
	if err != nil {
		return CertResult{Encrypted: false, Source: "disk"}, err
	}

	// Best-effort local validation: is it currently time-valid?
	// "AuthenticatedCA" here means "looks like a real cert and not expired" locally.
	// Sender-side authentication requires DANE/MTA-STS policies and is not implied by this flag.
	authCA := false
	if len(cert.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			if now.After(leaf.NotBefore) && now.Before(leaf.NotAfter) {
				authCA = true
			}
		}
	}

	return CertResult{
		Cert:            cert,
		Encrypted:       true,
		AuthenticatedCA: authCA,
		Source:          "disk",
	}, nil
}

