package creds

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

type quickVector struct {
	SPKIDERHex    string    `json:"spki_der_hex"`
	NotBefore     time.Time `json:"not_before"`
	NotBeforeUnix int64     `json:"not_before_unix"`
	ID            string    `json:"id"`
	Label         string    `json:"label"`
}

func loadQuickVectors(t *testing.T) []quickVector {
	t.Helper()
	b, err := os.ReadFile("testdata/quick_id.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct{ Vectors []quickVector }
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	return f.Vectors
}

func TestQuickIDVectors(t *testing.T) {
	for _, v := range loadQuickVectors(t) {
		spki, err := hex.DecodeString(v.SPKIDERHex)
		if err != nil {
			t.Fatal(err)
		}
		if v.NotBefore.Unix() != v.NotBeforeUnix {
			t.Fatalf("vector %s: not_before %s != %d", v.ID, v.NotBefore, v.NotBeforeUnix)
		}
		got := QuickID(spki, v.NotBefore)
		if got != v.ID {
			t.Errorf("QuickID = %s, want %s", got, v.ID)
		}
		if !IsQuickID(got) {
			t.Errorf("IsQuickID(%s) = false", got)
		}
		if h := QuickHostname(got, "hostingerpreview.dev"); h != v.Label+".hostingerpreview.dev" {
			t.Errorf("QuickHostname = %s", h)
		}
	}
}

func TestIsQuickID(t *testing.T) {
	for id, want := range map[string]bool{
		"153b4325-7e60-89b0-adf3-11b3455e487f":  true,
		"153B4325-7E60-89B0-ADF3-11B3455E487F":  true,
		"153b4325-7e60-89b0-bdf3-11b3455e487f":  true,
		"153b4325-7e60-49b0-adf3-11b3455e487f":  false, // v4: named
		"153b4325-7e60-89b0-cdf3-11b3455e487f":  false, // bad variant
		"153b4325-7e60-89b0-7df3-11b3455e487f":  false,
		"153b43257e6089b0adf311b3455e487f":      false,
		"153b4325-7e60-89b0-adf3-11b3455e487":   false,
		"153b4325-7e60-89b0-adf3-11b3455e487f0": false,
		"153b4325-7e60-89b0-adf3-11b3455e487g":  false,
		tid:                                     false,
	} {
		if got := IsQuickID(id); got != want {
			t.Errorf("IsQuickID(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestNewQuick(t *testing.T) {
	now := time.Date(2026, 10, 7, 14, 5, 7, 900_000_000, time.UTC)
	c, err := NewQuick([]string{"bnk.tunnel.example"}, now)
	if err != nil {
		t.Fatal(err)
	}
	leaf := c.Leaf
	if !IsQuickID(c.TunnelID) {
		t.Fatalf("tunnel id %s is not a quick id", c.TunnelID)
	}
	if want := time.Date(2026, 10, 7, 14, 0, 7, 0, time.UTC); !leaf.NotBefore.Equal(want) {
		t.Fatalf("NotBefore %s, want %s", leaf.NotBefore, want)
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) != QuickLifetime {
		t.Fatalf("lifetime %s", leaf.NotAfter.Sub(leaf.NotBefore))
	}
	if QuickID(leaf.RawSubjectPublicKeyInfo, leaf.NotBefore) != c.TunnelID {
		t.Fatal("id does not match the leaf")
	}
	if pub, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("want P-256, got %T", leaf.PublicKey)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != SANScheme+c.TunnelID {
		t.Fatalf("URI SANs %v", leaf.URIs)
	}
	if len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 {
		t.Fatal("no other SAN allowed")
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("EKU %v", leaf.ExtKeyUsage)
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature || leaf.IsCA {
		t.Fatalf("key usage %v, CA %v", leaf.KeyUsage, leaf.IsCA)
	}
	if leaf.SerialNumber.Sign() <= 0 || leaf.SerialNumber.BitLen() > 128 {
		t.Fatalf("serial %s", leaf.SerialNumber)
	}
	if !bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
		t.Fatal("leaf must be self-signed")
	}
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		t.Fatalf("self-signature: %v", err)
	}
	// The PEM round trip is the same check a credentials file gets.
	if _, err := FromPEM(c.TunnelID, []byte(c.CertificatePEM), []byte(c.PrivateKeyPEM), c.BootstrapEndpoints); err != nil {
		t.Fatalf("FromPEM: %v", err)
	}

	c2, err := NewQuick([]string{"bnk.tunnel.example"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if c2.TunnelID == c.TunnelID {
		t.Fatal("two quick tunnels must get two ids")
	}
	if _, err := NewQuick(nil, now); err == nil {
		t.Fatal("bootstrap is required")
	}
}

func TestQuickStoreWarnOff(t *testing.T) {
	c, err := NewQuick([]string{"bnk.tunnel.example"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	s, err := NewMemoryStore(c, slog.New(slog.NewTextHandler(&buf, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	s.warnIfExpiring()
	if !strings.Contains(buf.String(), "expires soon") {
		t.Fatalf("default store must warn for a 24 h leaf: %q", buf.String())
	}
	buf.Reset()
	s.SetWarnDays(0)
	s.warnIfExpiring()
	if buf.Len() != 0 {
		t.Fatalf("SetWarnDays(0) must turn the warning off: %q", buf.String())
	}
}
