// Package testpki builds throwaway CAs and certificates for tests.
package testpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	Pool *x509.CertPool
	PEM  []byte
}

func NewCA(t testing.TB) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "hCDN Tunnel Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{Cert: cert, Key: key, Pool: pool, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

var serial atomic.Int64

func nextSerial() *big.Int { return big.NewInt(100 + serial.Add(1)) }

// IssueClient returns PEM cert/key for a connector with URI SAN hcdn-tunnel:<id>.
func (ca *CA) IssueClient(t testing.TB, tunnelID string, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	return ca.IssueClientURIs(t, tunnelID, []*url.URL{{Scheme: "hcdn-tunnel", Opaque: tunnelID}}, notAfter)
}

// IssueClientURIs issues a client certificate with arbitrary URI SANs (negative tests).
func (ca *CA) IssueClientURIs(t testing.TB, cn string, uris []*url.URL, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: "hcdn-tunnel:" + cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
}

// IssueServer returns a server certificate for the given DNS names and 127.0.0.1/::1.
func (ca *CA) IssueServer(t testing.TB, names ...string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// WriteCredentials writes a credentials.json with mode 0600 and returns its path.
func (ca *CA) WriteCredentials(t testing.TB, dir, tunnelID string, bootstrap []string, notAfter time.Time) string {
	t.Helper()
	certPEM, keyPEM := ca.IssueClient(t, tunnelID, notAfter)
	return WriteCredentialsPEM(t, dir, tunnelID, certPEM, keyPEM, bootstrap, notAfter)
}

// WriteCredentialsPEM writes a credentials.json from the given PEMs (mode 0600).
func WriteCredentialsPEM(t testing.TB, dir, tunnelID string, certPEM, keyPEM []byte, bootstrap []string, notAfter time.Time) string {
	t.Helper()
	b, _ := json.Marshal(map[string]any{
		"tunnel_id":           tunnelID,
		"certificate_pem":     string(certPEM),
		"private_key_pem":     string(keyPEM),
		"bootstrap_endpoints": bootstrap,
		"not_after":           notAfter.UTC().Format(time.RFC3339),
	})
	p := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restrict(p); err != nil {
		t.Fatal(err)
	}
	return p
}
