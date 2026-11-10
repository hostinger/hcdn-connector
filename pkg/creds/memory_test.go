package creds

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hostinger/hcdn-connector/internal/testpki"
)

func memCreds(t *testing.T, ca *testpki.CA, tunnelID string, notAfter time.Time) *Credentials {
	t.Helper()
	certPEM, keyPEM := ca.IssueClient(t, tunnelID, notAfter)
	c, err := FromPEM(tunnelID, certPEM, keyPEM, []string{"bnk.tunnel.example"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFromPEM(t *testing.T) {
	ca := testpki.NewCA(t)
	exp := time.Now().Add(time.Hour)
	certPEM, keyPEM := ca.IssueClient(t, tid, exp)
	got, err := FromPEM(strings.ToUpper(tid), certPEM, keyPEM, []string{"bnk.tunnel.example"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"tunnel_id": tid, "certificate_pem": string(certPEM), "private_key_pem": string(keyPEM),
		"bootstrap_endpoints": []string{"bnk.tunnel.example"}})
	want, err := Parse(b, tid)
	if err != nil {
		t.Fatal(err)
	}
	if got.TunnelID != want.TunnelID || got.Serial != want.Serial || !got.NotAfter.Equal(want.NotAfter) ||
		strings.Join(got.BootstrapEndpoints, ",") != strings.Join(want.BootstrapEndpoints, ",") {
		t.Fatalf("FromPEM %+v != Parse %+v", got.File, want.File)
	}
	if _, err := FromPEM(tid, certPEM, keyPEM, nil); err == nil || !strings.Contains(err.Error(), "bootstrap_endpoints") {
		t.Fatalf("no bootstrap: %v", err)
	}
	if _, err := FromPEM("00000000-0000-0000-0000-000000000000", certPEM, keyPEM, []string{"x"}); err == nil || !strings.Contains(err.Error(), "SAN") {
		t.Fatalf("SAN mismatch: %v", err)
	}
}

func TestMemoryStoreReplace(t *testing.T) {
	ca := testpki.NewCA(t)
	s, err := NewMemoryStore(memCreds(t, ca, tid, time.Now().Add(time.Hour)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.Path() != "" || s.CanRefresh() || s.ExpiryHint() != "" {
		t.Fatalf("memory store: path=%q canRefresh=%v hint=%q", s.Path(), s.CanRefresh(), s.ExpiryHint())
	}
	var got *Credentials
	s.OnChange(func(c *Credentials) { got = c })
	if changed, err := s.Reload(); changed || err != nil {
		t.Fatalf("Reload on a memory store: %v %v", changed, err)
	}
	next := memCreds(t, ca, tid, time.Now().Add(2*time.Hour))
	if changed, err := s.Replace(next); !changed || err != nil {
		t.Fatalf("replace: %v %v", changed, err)
	}
	if got != next || s.Generation() != 1 || s.Current() != next {
		t.Fatalf("callback/generation: gen=%d", s.Generation())
	}
	if changed, err := s.Replace(next); changed || err != nil {
		t.Fatalf("same certificate: %v %v", changed, err)
	}
	other := memCreds(t, ca, "00000000-0000-0000-0000-000000000000", time.Now().Add(time.Hour))
	if _, err := s.Replace(other); !errors.Is(err, ErrTunnelIDMismatch) {
		t.Fatalf("another tunnel: %v", err)
	}
	if _, err := s.Replace(memCreds(t, ca, tid, time.Now().Add(-time.Minute))); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired: %v", err)
	}
	if s.Generation() != 1 {
		t.Fatal("a refused certificate must not bump the generation")
	}
	if _, err := NewMemoryStore(memCreds(t, ca, tid, time.Now().Add(-time.Minute)), nil, nil); err == nil {
		t.Fatal("an expired certificate must fail at start")
	}
	fs, err := NewStore(ca.WriteCredentials(t, t.TempDir(), tid, []string{"x.example"}, time.Now().Add(time.Hour)), tid, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Replace(next); err == nil || !strings.Contains(err.Error(), "memory store") {
		t.Fatalf("Replace on a file store: %v", err)
	}
}

func TestMemoryStoreRefresh(t *testing.T) {
	ca := testpki.NewCA(t)
	first := memCreds(t, ca, tid, time.Now().Add(time.Hour))
	next := first
	var fail error
	s, err := NewMemoryStore(first, nil, func(context.Context) (*Credentials, error) { return next, fail })
	if err != nil {
		t.Fatal(err)
	}
	if !s.CanRefresh() {
		t.Fatal("CanRefresh")
	}
	if err := s.Refresh(context.Background()); err == nil {
		t.Fatal("a refresh that returns the current certificate must fail")
	}
	fail = errors.New("enrollment down")
	if err := s.Refresh(context.Background()); !errors.Is(err, fail) {
		t.Fatalf("refresh error: %v", err)
	}
	fail, next = nil, memCreds(t, ca, tid, time.Now().Add(2*time.Hour))
	if err := s.Refresh(context.Background()); err != nil || s.Current() != next {
		t.Fatalf("refresh: %v", err)
	}
}

func TestMemoryStoreRefreshRaces(t *testing.T) {
	ca := testpki.NewCA(t)
	first := memCreds(t, ca, tid, time.Now().Add(time.Hour))
	replaced := memCreds(t, ca, tid, time.Now().Add(2*time.Hour))
	var s *Store
	s, err := NewMemoryStore(first, nil, func(context.Context) (*Credentials, error) {
		if _, err := s.Replace(replaced); err != nil {
			t.Error(err)
		}
		return replaced, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Refresh(context.Background()); err != nil || s.Current() != replaced {
		t.Fatalf("a Replace during the refresh must count as success: %v", err)
	}

	late := memCreds(t, ca, tid, time.Now().Add(3*time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	s2, err := NewMemoryStore(first, nil, func(context.Context) (*Credentials, error) { cancel(); return late, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Refresh(ctx); !errors.Is(err, context.Canceled) || s2.Current() != first {
		t.Fatalf("a result after the caller gave up must not be installed: %v", err)
	}
}

func TestStoreHooksRemove(t *testing.T) {
	ca := testpki.NewCA(t)
	s, err := NewMemoryStore(memCreds(t, ca, tid, time.Now().Add(time.Hour)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	remove := s.OnChange(func(*Credentials) { calls++ })
	keep := 0
	s.OnChange(func(*Credentials) { keep++ })
	remove()
	remove()
	var gauges [2]int
	removeG1 := s.SetGauge(func(float64) { gauges[0]++ })
	s.SetGauge(func(float64) { gauges[1]++ })
	removeG1() // the second setter replaced it: no effect
	if _, err := s.Replace(memCreds(t, ca, tid, time.Now().Add(2*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if calls != 0 || keep != 1 || gauges != [2]int{1, 2} {
		t.Fatalf("calls=%d keep=%d gauges=%v", calls, keep, gauges)
	}
	if _, err := s.Replace(&Credentials{File: File{TunnelID: tid}}); err == nil || !strings.Contains(err.Error(), "FromPEM") {
		t.Fatalf("hand-built credentials: %v", err)
	}
	if _, err := NewMemoryStore(&Credentials{}, nil, nil); err == nil {
		t.Fatal("hand-built credentials must fail at start")
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *syncBuf) Write(p []byte) (int, error) { w.mu.Lock(); defer w.mu.Unlock(); return w.b.Write(p) }
func (w *syncBuf) String() string              { w.mu.Lock(); defer w.mu.Unlock(); return w.b.String() }

func TestMemoryStoreWatch(t *testing.T) {
	ca := testpki.NewCA(t)
	var buf syncBuf
	s, err := NewMemoryStore(memCreds(t, ca, tid, time.Now().Add(10*24*time.Hour)), slog.New(slog.NewTextHandler(&buf, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	s.SetExpiryHint("renew it")
	gauge := make(chan float64, 4)
	s.SetGauge(func(d float64) { gauge <- d })
	<-gauge
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { s.Watch(stop, nil); close(done) }()
	select {
	case d := <-gauge:
		if d < 9 || d > 10 {
			t.Fatalf("gauge %v", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Watch did not set the gauge")
	}
	close(stop)
	<-done
	if !strings.Contains(buf.String(), "connector certificate expires soon; renew it") {
		t.Fatalf("expiry warning: %q", buf.String())
	}
}
