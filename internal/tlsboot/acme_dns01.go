package tlsboot

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sisumail/sisumail/internal/core"
	"golang.org/x/crypto/acme"
)

const letsEncryptDirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"

type ACMEDNS01Provider struct {
	Hostname       string
	ZoneName       string
	Email          string
	DirectoryURL   string
	DNSProvider    core.DNSProvider
	PresentDNS01   func(hostname, value string) (cleanup func(), err error)
	CertPath       string
	KeyPath        string
	AccountKeyPath string

	RenewBefore     time.Duration
	PropagationWait time.Duration
	IssueTimeout    time.Duration

	issueMu sync.Mutex
}

func (p *ACMEDNS01Provider) GetCertificate(now time.Time) (CertResult, error) {
	if p == nil {
		return CertResult{}, fmt.Errorf("nil acme provider")
	}
	if err := p.setDefaults(); err != nil {
		return CertResult{}, err
	}

	if cert, notAfter, err := loadDiskCertificateWithNotAfter(p.CertPath, p.KeyPath); err == nil {
		if notAfter.After(now.Add(p.RenewBefore)) {
			return CertResult{
				Cert:            cert,
				Encrypted:       true,
				AuthenticatedCA: true,
				Source:          "acme",
			}, nil
		}
	}

	p.issueMu.Lock()
	defer p.issueMu.Unlock()

	// Re-check inside lock to avoid duplicate renewals.
	if cert, notAfter, err := loadDiskCertificateWithNotAfter(p.CertPath, p.KeyPath); err == nil {
		if notAfter.After(now.Add(p.RenewBefore)) {
			return CertResult{
				Cert:            cert,
				Encrypted:       true,
				AuthenticatedCA: true,
				Source:          "acme",
			}, nil
		}
	}

	if err := p.issueOrRenew(now); err != nil {
		return CertResult{Encrypted: false, Source: "acme"}, err
	}
	cert, _, err := loadDiskCertificateWithNotAfter(p.CertPath, p.KeyPath)
	if err != nil {
		return CertResult{Encrypted: false, Source: "acme"}, err
	}
	return CertResult{
		Cert:            cert,
		Encrypted:       true,
		AuthenticatedCA: true,
		Source:          "acme",
	}, nil
}

func (p *ACMEDNS01Provider) setDefaults() error {
	if strings.TrimSpace(p.Hostname) == "" {
		return fmt.Errorf("missing acme hostname")
	}
	if strings.TrimSpace(p.ZoneName) == "" {
		return fmt.Errorf("missing acme zone")
	}
	if p.DNSProvider == nil && p.PresentDNS01 == nil {
		return fmt.Errorf("missing dns provider")
	}
	if strings.TrimSpace(p.CertPath) == "" || strings.TrimSpace(p.KeyPath) == "" || strings.TrimSpace(p.AccountKeyPath) == "" {
		return fmt.Errorf("missing cert/key/account paths")
	}
	if p.RenewBefore <= 0 {
		p.RenewBefore = 30 * 24 * time.Hour
	}
	if p.PropagationWait <= 0 {
		p.PropagationWait = 20 * time.Second
	}
	if p.IssueTimeout <= 0 {
		p.IssueTimeout = 4 * time.Minute
	}
	if strings.TrimSpace(p.DirectoryURL) == "" {
		p.DirectoryURL = letsEncryptDirectoryURL
	}
	return nil
}

func (p *ACMEDNS01Provider) issueOrRenew(now time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), p.IssueTimeout)
	defer cancel()

	acctKey, err := loadOrCreateAccountKey(p.AccountKeyPath)
	if err != nil {
		return fmt.Errorf("acme account key: %w", err)
	}

	client := &acme.Client{
		Key:          acctKey,
		DirectoryURL: p.DirectoryURL,
	}

	if err := registerAccount(ctx, client, p.Email); err != nil {
		return fmt.Errorf("acme register: %w", err)
	}

	order, err := client.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: p.Hostname}})
	if err != nil {
		return fmt.Errorf("acme order: %w", err)
	}

	var zoneID string
	if p.PresentDNS01 == nil {
		zoneID, err = p.DNSProvider.GetZoneIDByName(p.ZoneName)
		if err != nil {
			return fmt.Errorf("acme zone id: %w", err)
		}
	}

	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("acme authz: %w", err)
		}
		if authz.Status == acme.StatusValid {
			continue
		}

		ch, err := pickDNS01Challenge(authz)
		if err != nil {
			return err
		}
		record, err := client.DNS01ChallengeRecord(ch.Token)
		if err != nil {
			return fmt.Errorf("acme challenge record: %w", err)
		}

		var cleanup func()
		if p.PresentDNS01 != nil {
			cleanup, err = p.PresentDNS01(p.Hostname, record)
		} else {
			cleanup, err = p.presentDNS01Challenge(zoneID, record)
		}
		if err != nil {
			return fmt.Errorf("acme present challenge: %w", err)
		}
		if cleanup != nil {
			defer cleanup()
		}

		if _, err := client.Accept(ctx, ch); err != nil {
			return fmt.Errorf("acme accept challenge: %w", err)
		}
		if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil {
			return fmt.Errorf("acme wait authorization: %w", err)
		}
	}

	if _, err := client.WaitOrder(ctx, order.URI); err != nil {
		return fmt.Errorf("acme wait order: %w", err)
	}

	certPriv, csrDER, err := createCSR(p.Hostname)
	if err != nil {
		return fmt.Errorf("acme csr: %w", err)
	}
	chainDER, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return fmt.Errorf("acme create cert: %w", err)
	}
	if err := writeCertAndKey(p.CertPath, p.KeyPath, chainDER, certPriv); err != nil {
		return fmt.Errorf("acme write cert: %w", err)
	}
	_ = now // keeps signature stable if we later use jitter logic.
	return nil
}

func pickDNS01Challenge(authz *acme.Authorization) (*acme.Challenge, error) {
	if authz == nil {
		return nil, fmt.Errorf("nil authorization")
	}
	for _, ch := range authz.Challenges {
		if ch.Type == "dns-01" {
			return ch, nil
		}
	}
	return nil, fmt.Errorf("dns-01 challenge not offered")
}

func registerAccount(ctx context.Context, client *acme.Client, email string) error {
	var contact []string
	if strings.TrimSpace(email) != "" {
		contact = []string{"mailto:" + strings.TrimSpace(email)}
	}
	_, err := client.Register(ctx, &acme.Account{Contact: contact}, acme.AcceptTOS)
	if err == nil {
		return nil
	}
	// Treat already-registered as success.
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "already exists") || strings.Contains(msg, "already registered") || strings.Contains(msg, "account does not exist") {
		// "account does not exist" can be returned by some CAs when reusing keys across environments;
		// try UpdateReg in that case.
		if _, uerr := client.UpdateReg(ctx, &acme.Account{Contact: contact}); uerr == nil {
			return nil
		}
	}
	if ae, ok := err.(*acme.Error); ok && ae.StatusCode == 409 {
		return nil
	}
	return err
}

func (p *ACMEDNS01Provider) presentDNS01Challenge(zoneID, value string) (func(), error) {
	fqdn := "_acme-challenge." + strings.TrimSuffix(p.Hostname, ".")
	quoted := quoteTXT(value)

	existing, err := p.DNSProvider.GetRRSet(zoneID, fqdn, "TXT")
	if err != nil {
		return nil, err
	}
	values := []string{quoted}
	if existing != nil {
		values = mergeTXTValues(existing.Values, quoted)
	}
	if err := p.DNSProvider.UpsertRRSet(zoneID, core.DNSRRSet{
		Type:   "TXT",
		Name:   fqdn,
		TTL:    60,
		Values: values,
	}); err != nil {
		return nil, err
	}

	time.Sleep(p.PropagationWait)
	cleanup := func() {
		cur, err := p.DNSProvider.GetRRSet(zoneID, fqdn, "TXT")
		if err != nil || cur == nil {
			return
		}
		rest := removeTXTValue(cur.Values, quoted)
		if len(rest) == 0 {
			_ = p.DNSProvider.DeleteRRSet(zoneID, fqdn, "TXT")
			return
		}
		_ = p.DNSProvider.UpsertRRSet(zoneID, core.DNSRRSet{
			Type:   "TXT",
			Name:   fqdn,
			TTL:    cur.TTL,
			Values: rest,
		})
	}
	return cleanup, nil
}

func quoteTXT(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "\"") && strings.HasSuffix(v, "\"") {
		return v
	}
	return `"` + v + `"`
}

func normalizeTXT(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, `"`)
	v = strings.TrimSuffix(v, `"`)
	return v
}

func mergeTXTValues(existing []string, add string) []string {
	addNorm := normalizeTXT(add)
	out := make([]string, 0, len(existing)+1)
	seen := map[string]bool{}
	for _, v := range existing {
		n := normalizeTXT(v)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, quoteTXT(n))
	}
	if !seen[addNorm] && addNorm != "" {
		out = append(out, quoteTXT(addNorm))
	}
	return out
}

func removeTXTValue(existing []string, remove string) []string {
	rm := normalizeTXT(remove)
	var out []string
	for _, v := range existing {
		n := normalizeTXT(v)
		if n == "" || n == rm {
			continue
		}
		out = append(out, quoteTXT(n))
	}
	return out
}

func loadOrCreateAccountKey(path string) (*ecdsa.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("invalid pem")
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return key, nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemKey, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func createCSR(hostname string) (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: hostname},
		DNSNames: []string{hostname},
	}, key)
	if err != nil {
		return nil, nil, err
	}
	return key, csrDER, nil
}

func writeCertAndKey(certPath, keyPath string, certChainDER [][]byte, key *ecdsa.PrivateKey) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	var certPEM strings.Builder
	for _, der := range certChainDER {
		if err := pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return err
		}
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tmpCert := certPath + ".tmp"
	tmpKey := keyPath + ".tmp"
	if err := os.WriteFile(tmpCert, []byte(certPEM.String()), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(tmpKey, keyPEM, 0o600); err != nil {
		_ = os.Remove(tmpCert)
		return err
	}
	if err := os.Rename(tmpCert, certPath); err != nil {
		_ = os.Remove(tmpCert)
		_ = os.Remove(tmpKey)
		return err
	}
	if err := os.Rename(tmpKey, keyPath); err != nil {
		return err
	}
	return nil
}

func loadDiskCertificateWithNotAfter(certPath, keyPath string) (tls.Certificate, time.Time, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, time.Time{}, err
	}
	if len(cert.Certificate) == 0 {
		return tls.Certificate{}, time.Time{}, fmt.Errorf("empty certificate chain")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, time.Time{}, err
	}
	return cert, leaf.NotAfter, nil
}
