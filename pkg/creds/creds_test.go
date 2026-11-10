package creds

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hostinger/hcdn-connector/internal/testpki"
)

const tid = "3f9c2a7e-0b3e-4d0a-9d0a-1c8f5e7b2a11"

func TestLoad(t *testing.T) {
	ca := testpki.NewCA(t)
	p := ca.WriteCredentials(t, t.TempDir(), tid, []string{"bnk.tunnel.example"}, time.Now().Add(400*24*time.Hour))
	c, err := Load(p, tid)
	if err != nil {
		t.Fatal(err)
	}
	if c.TunnelID != tid || c.Serial == "" || len(c.BootstrapEndpoints) != 1 {
		t.Fatalf("bad credentials: %+v", c.File)
	}
	if d := c.DaysLeft(time.Now()); d < 399 || d > 401 {
		t.Fatalf("days left %v", d)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json"), tid); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing file: %v", err)
	}
}

func TestLoadRejectsTunnelIDMismatch(t *testing.T) {
	ca := testpki.NewCA(t)
	p := ca.WriteCredentials(t, t.TempDir(), tid, []string{"bnk.tunnel.example"}, time.Now().Add(time.Hour))
	if _, err := Load(p, "00000000-0000-0000-0000-000000000000"); err == nil {
		t.Fatal("expected tunnel_id mismatch")
	}
}

func TestLoadRequiresExactlyOneMatchingSAN(t *testing.T) {
	ca := testpki.NewCA(t)
	exp := time.Now().Add(time.Hour)
	other := "00000000-0000-0000-0000-000000000000"
	cases := map[string][]*url.URL{
		"missing SAN":     nil,
		"mismatching SAN": {{Scheme: "hcdn-tunnel", Opaque: other}},
		"two SANs":        {{Scheme: "hcdn-tunnel", Opaque: tid}, {Scheme: "hcdn-tunnel", Opaque: other}},
	}
	for name, uris := range cases {
		certPEM, keyPEM := ca.IssueClientURIs(t, tid, uris, exp)
		p := testpki.WriteCredentialsPEM(t, t.TempDir(), tid, certPEM, keyPEM, []string{"bnk.tunnel.example"}, exp)
		if _, err := Load(p, tid); err == nil || !strings.Contains(err.Error(), "SAN") {
			t.Errorf("%s: want a SAN error, got %v", name, err)
		}
	}
	// Unrelated URI SANs next to the one hcdn-tunnel SAN are fine; case differs.
	certPEM, keyPEM := ca.IssueClientURIs(t, tid, []*url.URL{{Scheme: "https", Host: "x.example"}, {Scheme: "hcdn-tunnel", Opaque: strings.ToUpper(tid)}}, exp)
	p := testpki.WriteCredentialsPEM(t, t.TempDir(), tid, certPEM, keyPEM, []string{"bnk.tunnel.example"}, exp)
	if _, err := Load(p, tid); err != nil {
		t.Fatalf("one matching SAN: %v", err)
	}
	// Key does not match the certificate.
	certPEM, _ = ca.IssueClient(t, tid, exp)
	_, otherKey := ca.IssueClient(t, tid, exp)
	p = testpki.WriteCredentialsPEM(t, t.TempDir(), tid, certPEM, otherKey, []string{"bnk.tunnel.example"}, exp)
	if _, err := Load(p, tid); err == nil || !strings.Contains(err.Error(), "certificate/key") {
		t.Fatalf("key/cert mismatch: %v", err)
	}
}

func TestStoreReloadDetectsChange(t *testing.T) {
	ca := testpki.NewCA(t)
	dir := t.TempDir()
	p := ca.WriteCredentials(t, dir, tid, []string{"bnk.tunnel.example"}, time.Now().Add(time.Hour))
	s, err := NewStore(p, tid, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	var got *Credentials
	s.OnChange(func(c *Credentials) { got = c })
	if changed, err := s.Reload(); err != nil || changed {
		t.Fatalf("unchanged reload: %v %v", changed, err)
	}
	old := s.Current().Serial
	ca.WriteCredentials(t, dir, tid, []string{"bnk.tunnel.example"}, time.Now().Add(2*time.Hour))
	changed, err := s.Reload()
	if err != nil || !changed {
		t.Fatalf("changed reload: %v %v", changed, err)
	}
	if got == nil || got.Serial == old || s.Generation() != 1 {
		t.Fatalf("callback/generation: %v gen=%d", got, s.Generation())
	}
	if crt, err := s.GetClientCertificate(nil); err != nil || crt.Leaf.SerialNumber.Text(16) != s.Current().Serial {
		t.Fatalf("GetClientCertificate: %v", err)
	}
}

func TestStoreReloadRefusesExpiredCertificate(t *testing.T) {
	ca := testpki.NewCA(t)
	dir := t.TempDir()
	p := ca.WriteCredentials(t, dir, tid, []string{"bnk.tunnel.example"}, time.Now().Add(2*time.Hour))
	s, err := NewStore(p, tid, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	good := s.Current().Serial
	// A restored backup whose certificate is already expired.
	ca.WriteCredentials(t, dir, tid, []string{"bnk.tunnel.example"}, time.Now().Add(-time.Minute))
	if changed, err := s.Reload(); err == nil || changed || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired reload: changed=%v err=%v", changed, err)
	}
	if s.Current().Serial != good || s.Generation() != 0 {
		t.Fatal("the working certificate must stay")
	}
	// Not valid yet (issued with NotBefore = now-1h): move the store clock back.
	ca.WriteCredentials(t, dir, tid, []string{"bnk.tunnel.example"}, time.Now().Add(3*time.Hour))
	s.now = func() time.Time { return time.Now().Add(-2 * time.Hour) }
	if changed, err := s.Reload(); err == nil || changed || !strings.Contains(err.Error(), "not valid before") {
		t.Fatalf("not-yet-valid reload: changed=%v err=%v", changed, err)
	}
	s.now = time.Now
	if changed, err := s.Reload(); err != nil || !changed {
		t.Fatalf("valid reload: changed=%v err=%v", changed, err)
	}
}

func TestNewStoreRefusesExpiredCertificate(t *testing.T) {
	ca := testpki.NewCA(t)
	p := ca.WriteCredentials(t, t.TempDir(), tid, []string{"bnk.tunnel.example"}, time.Now().Add(-time.Minute))
	if _, err := NewStore(p, tid, slog.Default()); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("an expired certificate must fail at start: %v", err)
	}
}

// Mirrors the server-side CSR check: a CSR that fails here gets 400
// from POST /v2/tunnels/:id/certificates.
func checkConnectorCSR(t *testing.T, csrPEM []byte) *x509.CertificateRequest {
	t.Helper()
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatalf("want exactly one CERTIFICATE REQUEST block:\n%s", csrPEM)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("signature: %v", err)
	}
	if pub, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("want an ECDSA P-256 key, got %T", csr.PublicKey)
	}
	if len(csr.Subject.Names) != 0 {
		t.Fatalf("subject must be empty, got %q", csr.Subject.String())
	}
	if len(csr.URIs)+len(csr.DNSNames)+len(csr.IPAddresses)+len(csr.EmailAddresses) != 0 {
		t.Fatal("CSR must carry no SANs")
	}
	for _, ext := range append(csr.Extensions, csr.ExtraExtensions...) {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			t.Fatal("CSR must not carry a subjectAltName extension")
		}
	}
	return csr
}

func TestGenerateCSR(t *testing.T) {
	keyPEM, csrPEM, err := GenerateCSR()
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil || kb.Type != "EC PRIVATE KEY" {
		t.Fatal("key pem")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	csr := checkConnectorCSR(t, csrPEM)
	if !key.PublicKey.Equal(csr.PublicKey) {
		t.Fatal("CSR public key does not match the private key")
	}
}

func TestWriteCSR(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key.pem")
	csrPath := filepath.Join(dir, "csr.pem")
	if err := WriteCSR(key, csrPath); err != nil {
		t.Fatal(err)
	}
	assertPrivate(t, key)
	if b, err := os.ReadFile(key); err != nil || !strings.Contains(string(b), "EC PRIVATE KEY") {
		t.Fatalf("key content: %v", err)
	}
	csrPEM, err := os.ReadFile(csrPath)
	if err != nil {
		t.Fatal(err)
	}
	checkConnectorCSR(t, csrPEM)
	if err := WriteCSR(key, csrPath); err == nil {
		t.Fatal("must not overwrite an existing key")
	}
}
