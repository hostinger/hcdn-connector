package connector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/hostinger/hcdn-connector/internal/proto"
	"github.com/hostinger/hcdn-connector/internal/testedge"
	"github.com/hostinger/hcdn-connector/internal/testpki"
	"github.com/hostinger/hcdn-connector/pkg/config"
	"github.com/hostinger/hcdn-connector/pkg/creds"
)

const tid = "3f9c2a7e-0b3e-4d0a-9d0a-1c8f5e7b2a11"

type rig struct {
	ca   *testpki.CA
	edge *testedge.Edge
	cfg  *config.Config
	svc  *httptest.Server
}

// newRig builds a config in code against a fake edge (auto mode, one PoP, one session).
func newRig(t *testing.T) *rig {
	t.Helper()
	ca := testpki.NewCA(t)
	edge := testedge.New(t, ca, "bnk", false)
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hi from "+r.Host) }))
	t.Cleanup(svc.Close)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, ca.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.TunnelID = tid
	cfg.ServerCAFile = caFile
	cfg.Ports = []int{edge.Port()}
	cfg.HomePops, cfg.SessionsPerPop = 1, 1
	cfg.AddRule(config.NewIngressRule("shop.example.com", svc.URL))
	return &rig{ca: ca, edge: edge, cfg: cfg, svc: svc}
}

func (r *rig) memStore(t *testing.T, exp time.Duration, refresh creds.RefreshFunc) *creds.Store {
	t.Helper()
	certPEM, keyPEM := r.ca.IssueClient(t, tid, time.Now().Add(exp))
	c, err := creds.FromPEM(tid, certPEM, keyPEM, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := creds.NewMemoryStore(c, nil, refresh)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func start(t *testing.T, c *Connector) (cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan error, 1)
	stopped := make(chan struct{})
	go func() { ch <- c.Run(ctx); close(stopped) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(20 * time.Second):
			t.Error("Run did not return")
		}
		c.Close()
	})
	return cancel, ch
}

func waitCond(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met in 10 s")
}

func TestFacadeRunReady(t *testing.T) {
	r := newRig(t)
	c, err := New(Options{Config: r.cfg, Credentials: r.memStore(t, 400*24*time.Hour, nil), Version: "9.9.9-test", LogOutput: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if c.Ready() || c.Status().TunnelID != tid || c.Status().Version != "9.9.9-test" {
		t.Fatalf("before Run: ready=%v status=%+v", c.Ready(), c.Status())
	}
	start(t, c)
	s := r.edge.WaitSession(t)
	if s.HelloErr != nil || s.Hello.Header.Get(proto.HdrConnVersion) != "9.9.9-test" {
		t.Fatalf("hello: %v %v", s.HelloErr, s.Hello)
	}
	waitCond(t, c.Ready)
	st := c.Status()
	if len(st.Pops) != 1 || st.Pops[0].Pop != "bnk" || st.Pops[0].Ready != 1 {
		t.Fatalf("status pops: %+v", st.Pops)
	}
	res := s.Get(t, "shop.example.com", "/")
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || string(body) != "hi from shop.example.com" {
		t.Fatalf("proxied: %d %q", res.StatusCode, body)
	}
	if res := s.Get(t, "other.example.com", "/"); res.StatusCode != 404 {
		t.Fatalf("catch-all from Default(): %d", res.StatusCode)
	}
	if err := c.Run(context.Background()); err == nil {
		t.Fatal("a second Run must fail")
	}
}

func TestFacadeRevokedExit(t *testing.T) {
	r := newRig(t)
	type exitCall struct {
		code int
		pops int
	}
	exits := make(chan exitCall, 2)
	var c *Connector
	c, err := New(Options{Config: r.cfg, Credentials: r.memStore(t, 400*24*time.Hour, nil), LogOutput: io.Discard,
		OnExit: func(code int) { exits <- exitCall{code, len(c.Status().Pops)} }})
	if err != nil {
		t.Fatal(err)
	}
	_, done := start(t, c)
	s := r.edge.WaitSession(t)
	waitCond(t, c.Ready)
	s.Goaway(t, proto.ReasonRevoked, 0)
	select {
	case e := <-exits:
		if e.code != proto.ExitRevoked || e.pops != 1 {
			t.Fatalf("OnExit(%d) with %d pops: it must run before the drain stops the supervisors", e.code, e.pops)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("OnExit not called")
	}
	select {
	case err := <-done:
		var ee *ExitError
		if !errors.As(err, &ee) || ee.Code != proto.ExitRevoked {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
	if len(exits) != 0 {
		t.Fatal("OnExit must run once")
	}
}

func TestFacadeReload(t *testing.T) {
	r := newRig(t)
	dir := t.TempDir()
	r.cfg.CredentialsFile = r.ca.WriteCredentials(t, dir, tid, []string{"127.0.0.1"}, time.Now().Add(400*24*time.Hour))
	reload := make(chan os.Signal, 1)
	c, err := New(Options{Config: r.cfg, Reload: reload, LogOutput: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	start(t, c)
	r.edge.WaitSession(t)
	r.ca.WriteCredentials(t, dir, tid, []string{"127.0.0.1"}, time.Now().Add(401*24*time.Hour))
	reload <- os.Interrupt
	waitCond(t, func() bool { return c.Creds().Generation() == 1 })

	// A nil Reload channel is accepted.
	r2 := newRig(t)
	c2, err := New(Options{Config: r2.cfg, Credentials: r2.memStore(t, 400*24*time.Hour, nil), LogOutput: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	start(t, c2)
	r2.edge.WaitSession(t)
}

func TestFacadeCredsMismatch(t *testing.T) {
	r := newRig(t)
	path := r.ca.WriteCredentials(t, t.TempDir(), tid, []string{"127.0.0.1"}, time.Now().Add(time.Hour))
	cases := map[string]func() Options{
		"both sources": func() Options {
			cfg := *r.cfg
			cfg.CredentialsFile = path
			return Options{Config: &cfg, Credentials: r.memStore(t, 400*24*time.Hour, nil)}
		},
		"no source": func() Options { cfg := *r.cfg; return Options{Config: &cfg} },
		"tunnel id mismatch": func() Options {
			cfg := *r.cfg
			cfg.TunnelID = "00000000-0000-0000-0000-000000000000"
			return Options{Config: &cfg, Credentials: r.memStore(t, 400*24*time.Hour, nil)}
		},
		"file tunnel id mismatch": func() Options {
			cfg := *r.cfg
			cfg.TunnelID, cfg.CredentialsFile = "00000000-0000-0000-0000-000000000000", path
			return Options{Config: &cfg}
		},
		"no config": func() Options { return Options{} },
	}
	for name, opts := range cases {
		o := opts()
		o.LogOutput = io.Discard
		if _, err := New(o); err == nil {
			t.Errorf("%s: New must fail", name)
		}
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *syncBuf) Write(p []byte) (int, error) { w.mu.Lock(); defer w.mu.Unlock(); return w.b.Write(p) }
func (w *syncBuf) String() string              { w.mu.Lock(); defer w.mu.Unlock(); return w.b.String() }

func TestFacadeCallerLogTee(t *testing.T) {
	r := newRig(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.cfg.Ports = []int{ln.Addr().(*net.TCPAddr).Port}
	ln.Close() // discovery fails: the manager logs at error level
	var buf syncBuf
	c, err := New(Options{Config: r.cfg, Credentials: r.memStore(t, 400*24*time.Hour, nil), Log: slog.New(slog.NewTextHandler(&buf, nil))})
	if err != nil {
		t.Fatal(err)
	}
	start(t, c)
	waitCond(t, func() bool {
		for _, e := range c.Status().LastErrors {
			if strings.Contains(e.Message, "discovery failed") {
				return true
			}
		}
		return false
	})
	if !strings.Contains(buf.String(), "discovery failed") {
		t.Fatalf("the caller logger must still get the record: %q", buf.String())
	}
}

func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetGauge().GetValue()
}

func TestFacadeSharedStore(t *testing.T) {
	r := newRig(t)
	store := r.memStore(t, 10*24*time.Hour, nil)
	cfg := r.cfg.Clone()
	cfg.TunnelID = strings.ToUpper(tid)
	var buf syncBuf
	c1, err := New(Options{Config: cfg, Credentials: store, Log: slog.New(slog.NewTextHandler(&buf, nil)),
		Hints: &Hints{CertExpiry: "enroll again"}})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TunnelID != strings.ToUpper(tid) {
		t.Fatal("New must not change the caller's Config")
	}
	cancel, done := start(t, c1)
	waitCond(t, func() bool {
		for _, e := range c1.Status().LastErrors {
			if strings.Contains(e.Message, "expires soon; enroll again") {
				return true
			}
		}
		return false
	})
	cancel()
	<-done
	c1.Close()

	c2, err := New(Options{Config: r.cfg, Credentials: store, LogOutput: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	certPEM, keyPEM := r.ca.IssueClient(t, tid, time.Now().Add(20*24*time.Hour))
	next, err := creds.FromPEM(tid, certPEM, keyPEM, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Replace(next); err != nil {
		t.Fatal(err)
	}
	if d1, d2 := gaugeValue(t, c1.Metrics().CertDaysLeft), gaugeValue(t, c2.Metrics().CertDaysLeft); d1 > 11 || d2 < 19 {
		t.Fatalf("a closed connector must not follow the store: days_left closed=%.1f open=%.1f", d1, d2)
	}
}

func TestFacadeCheckRows(t *testing.T) {
	r := newRig(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := "http://" + ln.Addr().String()
	ln.Close()
	r.cfg.AddRule(config.NewIngressRule("*.dead.example", dead))
	c, err := New(Options{Config: r.cfg, Credentials: r.memStore(t, 400*24*time.Hour, nil), LogOutput: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rows, err := c.Check(context.Background(), CheckOptions{Whoami: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []CheckRow{
		{Kind: CheckIngress, Name: "shop.example.com", Target: r.svc.URL, OK: true},
		{Kind: CheckIngress, Name: "*.dead.example", Target: dead, Class: proto.ErrServiceUnreachable},
		{Kind: CheckIngress, Name: CatchAllName, Target: "http_status:404", OK: true},
		{Kind: CheckWhoami, Name: "whoami", Target: "via 127.0.0.1: tunnel " + tid + " serial 1 days_left 100 pop bnk node bnk-edge1", OK: true},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows: %+v", rows)
	}
	for i, w := range want {
		g := rows[i]
		if g.Kind != w.Kind || g.Name != w.Name || g.Target != w.Target || g.OK != w.OK || g.Class != w.Class || (g.OK != (g.Err == "")) {
			t.Fatalf("row %d: got %+v, want %+v", i, g, w)
		}
	}
}

func TestServerCAFileAndPinsWiring(t *testing.T) {
	ca := testpki.NewCA(t)
	dir := t.TempDir()
	credsPath := ca.WriteCredentials(t, dir, tid, []string{"bnk.tunnel.example"}, time.Now().Add(time.Hour))
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, ca.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(ca.Cert.RawSubjectPublicKeyInfo)
	pin := "sha256/" + base64.StdEncoding.EncodeToString(sum[:])
	cfg, err := config.Parse([]byte(`
tunnel_id: ` + tid + `
credentials_file: ` + credsPath + `
server_ca_file: ` + caFile + `
server_spki_pins: ["` + pin + `"]
ports: [8443]
ingress:
  - service: http_status:404
`))
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{Config: cfg, LogOutput: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if c.dialer.RootCAs == nil || !c.dialer.RootCAs.Equal(ca.Pool) {
		t.Fatal("server_ca_file must replace the system roots")
	}
	if len(c.dialer.Pins) != 1 || !bytes.Equal(c.dialer.Pins[0], sum[:]) {
		t.Fatalf("pins: %x", c.dialer.Pins)
	}
	// A CA file without certificates is refused.
	if err := os.WriteFile(caFile, []byte("nothing"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Config: cfg, LogOutput: io.Discard}); err == nil || !strings.Contains(err.Error(), "server_ca_file") {
		t.Fatalf("empty CA file: %v", err)
	}
}

// Named mode guards every service dial too; AllowLocalPorts opts a port out.
func TestFacadeLocalPortGuard(t *testing.T) {
	r := newRig(t)
	r.cfg.AddRule(config.NewIngressRule("redis.example.com", "http://127.0.0.1:6379"))
	store := r.memStore(t, 400*24*time.Hour, nil)
	c, err := New(Options{Config: r.cfg, Credentials: store, LogOutput: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.Check(context.Background(), CheckOptions{})
	c.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !rows[0].OK {
		t.Fatalf("an allowed port was refused: %+v", rows[0])
	}
	if g := rows[1]; g.OK || g.Class != proto.ErrServiceUnreachable || !strings.Contains(g.Err, "port 6379 is not shared") {
		t.Fatalf("blocked row: %+v", g)
	}

	c, err = New(Options{Config: r.cfg, Credentials: store, LogOutput: io.Discard, AllowLocalPorts: []int{6379}})
	if err != nil {
		t.Fatal(err)
	}
	rows, err = c.Check(context.Background(), CheckOptions{})
	c.Close()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rows[1].Err, "is not shared") {
		t.Fatalf("AllowLocalPorts did not opt 6379 out: %+v", rows[1])
	}

	if _, err := New(Options{Config: r.cfg, Credentials: store, AllowLocalPorts: []int{70000}}); err == nil {
		t.Fatal("AllowLocalPorts must be ports")
	}
}
