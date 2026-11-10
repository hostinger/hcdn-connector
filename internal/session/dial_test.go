package session

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hostinger/hcdn-connector/internal/h2srv"
	"github.com/hostinger/hcdn-connector/internal/ingress"
	"github.com/hostinger/hcdn-connector/internal/metrics"
	"github.com/hostinger/hcdn-connector/internal/proto"
	"github.com/hostinger/hcdn-connector/internal/testedge"
	"github.com/hostinger/hcdn-connector/internal/testpki"
	"github.com/hostinger/hcdn-connector/pkg/config"
	"github.com/hostinger/hcdn-connector/pkg/creds"
)

const tid = "3f9c2a7e-0b3e-4d0a-9d0a-1c8f5e7b2a11"

type netipAddr = netip.Addr

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func newCreds(t *testing.T, ca *testpki.CA, bootstrap ...string) *creds.Store {
	t.Helper()
	p := ca.WriteCredentials(t, t.TempDir(), tid, bootstrap, time.Now().Add(400*24*time.Hour))
	s, err := creds.NewStore(p, tid, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func deadPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

func newDialer(t *testing.T, ca *testpki.CA, cs *creds.Store, ports []int, fallbackPort int) *Dialer {
	t.Helper()
	return &Dialer{
		Creds: cs, RootCAs: ca.Pool, Ports: NewPortMemory(ports), FallbackPort: fallbackPort,
		ConnectTimeout: 2 * time.Second, HappyEyeballsDelay: 50 * time.Millisecond, Version: "test", Log: slog.Default(),
	}
}

func serveSession(t *testing.T, conn *Conn, handler http.Handler) *h2srv.Session {
	t.Helper()
	s := h2srv.New(conn, h2srv.Options{Handler: handler, Version: "0.1.0-test", ConnectorID: "cid", Transport: conn.Transport})
	go func() { _ = s.Serve(context.Background()) }()
	t.Cleanup(s.Close)
	return s
}

// tlsProbe records whether x/net saw the TLS state through session.Conn (r.TLS).
type tlsProbe struct {
	mu   sync.Mutex
	seen []*tls.ConnectionState
}

func (p *tlsProbe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.seen = append(p.seen, r.TLS)
	p.mu.Unlock()
	w.WriteHeader(204)
}

func (p *tlsProbe) last() *tls.ConnectionState {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.seen) == 0 {
		return nil
	}
	return p.seen[len(p.seen)-1]
}

func TestDialDirectOffersSessionALPN(t *testing.T) {
	ca := testpki.NewCA(t)
	edge := testedge.New(t, ca, "bnk", false)
	d := newDialer(t, ca, newCreds(t, ca, "127.0.0.1"), []int{edge.Port(), deadPort(t)}, deadPort(t))
	conn, err := d.Dial(context.Background(), "127.0.0.1", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.Transport != proto.TransportDirect || conn.Port != edge.Port() {
		t.Fatalf("transport %s port %d", conn.Transport, conn.Port)
	}
	probe := &tlsProbe{}
	serveSession(t, conn, probe)
	s := edge.WaitSession(t)
	if s.HelloErr != nil || s.Hello.StatusCode != 200 || s.Hello.Header.Get(proto.HdrTransport) != proto.TransportDirect {
		t.Fatalf("hello over direct: %v %v", s.HelloErr, s.Hello)
	}
	s.Get(t, "x.example", "/").Body.Close()
	if cs := probe.last(); cs == nil || cs.NegotiatedProtocol != proto.ALPNSession || cs.Version != tls.VersionTLS13 {
		t.Fatalf("r.TLS must reflect the dialed connection, got %+v", cs)
	}
	if alpns := edge.OfferedALPNs(); len(alpns) != 1 || !reflect.DeepEqual(alpns[0], []string{proto.ALPNSession}) {
		t.Fatalf("offered ALPN %v", alpns)
	}
	if d.Ports.Working("127.0.0.1") != edge.Port() {
		t.Fatal("working port not remembered")
	}
}

func TestDialFallsBackTo443Upgrade(t *testing.T) {
	// coalesce=true: the 101 and the h2 preface arrive in one segment, so the
	// connector must replay the bytes buffered past the 101 (prefixConn).
	for _, coalesce := range []bool{false, true} {
		t.Run(map[bool]string{false: "two_writes", true: "one_write"}[coalesce], func(t *testing.T) {
			ca := testpki.NewCA(t)
			nginx := testedge.New(t, ca, "bnk", true)
			nginx.Coalesce = coalesce
			svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "via 443") }))
			defer svc.Close()
			tbl, err := ingress.Build([]config.IngressRule{
				{Hostname: "shop.example.com", Service: svc.URL, OriginRequest: config.OriginRequest{ConnectTimeout: time.Second, ResponseHeaderTimeout: time.Second, KeepaliveConnections: 2}},
				{Service: "http_status:404"},
			}, tid, nil)
			if err != nil {
				t.Fatal(err)
			}
			probe := &tlsProbe{}
			handler := ingress.NewHandler(tbl, tid, slog.Default(), metrics.New())
			both := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				probe.mu.Lock()
				probe.seen = append(probe.seen, r.TLS)
				probe.mu.Unlock()
				handler.ServeHTTP(w, r)
			})

			dead := deadPort(t)
			d := newDialer(t, ca, newCreds(t, ca, "127.0.0.1"), []int{dead, nginx.Port()}, nginx.Port())
			conn, err := d.Dial(context.Background(), "127.0.0.1", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if conn.Transport != proto.TransportFallback || conn.Port != nginx.Port() {
				t.Fatalf("transport %s port %d", conn.Transport, conn.Port)
			}
			if _, isPrefix := conn.Conn.(*prefixConn); coalesce && !isPrefix {
				t.Fatal("coalesced 101+preface must take the buffered-bytes path")
			}
			if alpns := nginx.OfferedALPNs(); len(alpns) != 1 || !reflect.DeepEqual(alpns[0], []string{proto.ALPNHTTP1}) {
				t.Fatalf("offered ALPN on 443 %v", alpns)
			}
			// ServeConn on the same connection after the 101: the edge's h2 client works.
			serveSession(t, conn, both)
			s := nginx.WaitSession(t)
			if s.HelloErr != nil || s.Hello.StatusCode != 200 {
				t.Fatalf("hello over 443: %v", s.HelloErr)
			}
			if s.Hello.Header.Get(proto.HdrTransport) != proto.TransportFallback {
				t.Fatalf("hcdn-transport %q", s.Hello.Header.Get(proto.HdrTransport))
			}
			res := s.Get(t, "shop.example.com", "/x")
			body, _ := io.ReadAll(res.Body)
			if res.StatusCode != 200 || string(body) != "via 443" || res.Header.Get(proto.HdrConnectorRT) == "" {
				t.Fatalf("proxied over 443: %d %q %v", res.StatusCode, body, res.Header)
			}
			if cs := probe.last(); cs == nil || cs.NegotiatedProtocol != proto.ALPNHTTP1 {
				t.Fatalf("r.TLS through prefixConn: %+v", cs)
			}
			if o := d.Ports.Order("127.0.0.1"); o[0] != nginx.Port() {
				t.Fatalf("working port must be tried first next time: %v", o)
			}
		})
	}
}

func TestDialSPKIPins(t *testing.T) {
	ca := testpki.NewCA(t)
	edge := testedge.New(t, ca, "bnk", false)
	nginx := testedge.New(t, ca, "bnk", true)
	sum := sha256.Sum256(ca.Cert.RawSubjectPublicKeyInfo)
	d := newDialer(t, ca, newCreds(t, ca, "127.0.0.1"), []int{edge.Port(), nginx.Port()}, nginx.Port())
	d.Pins = [][]byte{sum[:]}
	conn, err := d.Dial(context.Background(), "127.0.0.1", nil, nil)
	if err != nil {
		t.Fatalf("matching CA pin: %v", err)
	}
	conn.Close()

	bad := sha256.Sum256([]byte("not the key"))
	d2 := newDialer(t, ca, newCreds(t, ca, "127.0.0.1"), []int{edge.Port(), nginx.Port()}, nginx.Port())
	d2.Pins = [][]byte{bad[:]}
	if _, err := d2.Dial(context.Background(), "127.0.0.1", nil, nil); !errors.Is(err, ErrNotNetwork) || !strings.Contains(err.Error(), "server_spki_pins") {
		t.Fatalf("mismatching pin must fail closed without fallback: %v", err)
	}
	if len(nginx.OfferedALPNs()) != 0 {
		t.Fatal("a pin mismatch must not trigger the 443 fallback")
	}
}

func TestNginxStubRejectsUnknownALPN(t *testing.T) {
	ca := testpki.NewCA(t)
	nginx := testedge.New(t, ca, "bnk", true)
	d := newDialer(t, ca, newCreds(t, ca, "127.0.0.1"), []int{nginx.Port()}, nginx.Port())
	addrs, _ := d.Resolve(context.Background(), "127.0.0.1")
	if _, _, _, err := d.handshake(context.Background(), "127.0.0.1", addrs, nginx.Port(), proto.ALPNSession, nil); err == nil {
		t.Fatal("nginx must abort a handshake whose ALPN list lacks http/1.1 and h2")
	}
	tc, _, _, err := d.handshake(context.Background(), "127.0.0.1", addrs, nginx.Port(), proto.ALPNHTTP1, nil)
	if err != nil {
		t.Fatal(err)
	}
	tc.Close()
	if d.ALPN(nginx.Port(), false) != proto.ALPNHTTP1 || d.ALPN(nginx.Port(), true) != proto.ALPNHTTP1 ||
		d.ALPN(7844, false) != proto.ALPNSession || d.ALPN(7844, true) != proto.ALPNAPI {
		t.Fatal("ALPN per port")
	}
}

func TestDialCertificateErrorDoesNotFallBack(t *testing.T) {
	ca := testpki.NewCA(t)
	otherCA := testpki.NewCA(t)
	edge := testedge.New(t, ca, "bnk", false)
	nginx := testedge.New(t, ca, "bnk", true)
	d := newDialer(t, otherCA, newCreds(t, ca, "127.0.0.1"), []int{edge.Port(), nginx.Port()}, nginx.Port())
	_, err := d.Dial(context.Background(), "127.0.0.1", nil, nil)
	if !errors.Is(err, ErrNotNetwork) {
		t.Fatalf("want ErrNotNetwork, got %v", err)
	}
	if len(nginx.OfferedALPNs()) != 0 {
		t.Fatal("a certificate failure must not trigger the 443 fallback")
	}
}

func TestDialRemoteAlertDoesNotFallBack(t *testing.T) {
	ca := testpki.NewCA(t)
	primary := testedge.New(t, ca, "bnk", true) // aborts the session ALPN with no_application_protocol
	nginx := testedge.New(t, ca, "bnk", true)
	d := newDialer(t, ca, newCreds(t, ca, "127.0.0.1"), []int{primary.Port(), nginx.Port()}, nginx.Port())
	_, err := d.Dial(context.Background(), "127.0.0.1", nil, nil)
	if !errors.Is(err, ErrNotNetwork) {
		t.Fatalf("want ErrNotNetwork, got %v", err)
	}
	if len(nginx.OfferedALPNs()) != 0 {
		t.Fatal("a remote TLS alert must not trigger the 443 fallback")
	}
	if e := d.Ports.entries["127.0.0.1"]; e != nil && !e.lastPrimaryT.IsZero() {
		t.Fatal("a remote TLS alert is not a primary-port network failure")
	}
}

// TLS 1.3: the client-cert rejection is a post-handshake alert; it must surface
// from Serve (not a bare "closed before hello") and never trigger the 443 fallback.
func TestDialClientCertRejectedSurfacesAlert(t *testing.T) {
	ca := testpki.NewCA(t)
	otherCA := testpki.NewCA(t)
	edge := testedge.New(t, ca, "bnk", false)
	nginx := testedge.New(t, ca, "bnk", true)
	d := newDialer(t, ca, newCreds(t, otherCA, "127.0.0.1"), []int{edge.Port(), nginx.Port()}, nginx.Port())
	conn, err := d.Dial(context.Background(), "127.0.0.1", nil, nil)
	if err != nil {
		t.Fatalf("TLS 1.3 client side completes before the server verdict: %v", err)
	}
	defer conn.Close()
	s := h2srv.New(conn, h2srv.Options{Handler: http.NotFoundHandler(), Version: "v", ConnectorID: "c", Transport: conn.Transport})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = s.Serve(ctx)
	if err == nil || !strings.Contains(err.Error(), "certificate") || s.Hello() != nil {
		t.Fatalf("want a certificate alert before hello, got %v (hello %v)", err, s.Hello())
	}
	if len(nginx.OfferedALPNs()) != 0 {
		t.Fatal("a rejected client certificate must not trigger the 443 fallback")
	}
}

func TestDialUpgradeRefused(t *testing.T) {
	ca := testpki.NewCA(t)
	nginx := testedge.New(t, ca, "bnk", true)
	nginx.RejectAll = true
	d := newDialer(t, ca, newCreds(t, ca, "127.0.0.1"), []int{nginx.Port()}, nginx.Port())
	_, err := d.Dial(context.Background(), "127.0.0.1", nil, nil)
	if !errors.Is(err, ErrNotNetwork) || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want refused upgrade, got %v", err)
	}
}

// headerFlood answers every TLS connection with status and then header lines
// until the client hangs up.
func headerFlood(t *testing.T, ca *testpki.CA, status string) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{ca.IssueServer(t, "localhost")},
		NextProtos:   []string{proto.ALPNHTTP1, proto.ALPNAPI},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	line := []byte("X-Flood: " + strings.Repeat("a", 1000) + "\r\n")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if _, err := io.WriteString(c, "HTTP/1.1 "+status+"\r\n"); err != nil {
					return
				}
				for {
					if _, err := c.Write(line); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// countConn counts the raw bytes read from the peer.
type countConn struct {
	net.Conn
	n int
}

func (c *countConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.n += n
	return n, err
}

func TestResponseHeaderCapped(t *testing.T) {
	ca := testpki.NewCA(t)
	d := newDialer(t, ca, newCreds(t, ca, "127.0.0.1"), nil, 0)
	d.ConnectTimeout = 5 * time.Second
	cases := map[string]struct {
		status, alpn string
		read         func(context.Context, *tls.Conn) error
	}{
		"upgrade": {"101 Switching Protocols", proto.ALPNHTTP1, func(ctx context.Context, tc *tls.Conn) error {
			_, err := d.upgrade(ctx, tc, "127.0.0.1")
			return err
		}},
		"ping": {"200 OK", proto.ALPNAPI, func(ctx context.Context, tc *tls.Conn) error {
			ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
			defer cancel()
			return ping(ctx, tc, "127.0.0.1", 443, "test")
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			raw, err := net.Dial("tcp", headerFlood(t, ca, tc.status))
			if err != nil {
				t.Fatal(err)
			}
			cc := &countConn{Conn: raw}
			conn := tls.Client(cc, d.tlsConfig("127.0.0.1", tc.alpn, nil))
			defer conn.Close()
			if err := conn.Handshake(); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			err = tc.read(context.Background(), conn)
			if !errors.Is(err, ErrNotNetwork) || !strings.Contains(err.Error(), "response header exceeds") {
				t.Fatalf("want the header cap error, got %v", err)
			}
			if el := time.Since(start); el > time.Second {
				t.Fatalf("the cap must fail fast, not at the deadline: %v", el)
			}
			// The cap plus TLS framing and read-ahead.
			if cc.n > 2*proto.MaxHeaderBytes {
				t.Fatalf("read %d bytes from the peer, cap is %d", cc.n, proto.MaxHeaderBytes)
			}
		})
	}
}

func TestDialExclusions(t *testing.T) {
	ca := testpki.NewCA(t)
	edge := testedge.New(t, ca, "bnk", false)
	d := newDialer(t, ca, newCreds(t, ca, "127.0.0.1"), []int{edge.Port()}, deadPort(t))
	hard := map[netipAddr]bool{mustAddr("127.0.0.1"): true}
	if _, err := d.Dial(context.Background(), "127.0.0.1", hard, nil); !errors.Is(err, ErrNoAddress) {
		t.Fatalf("hard exclusion: %v", err)
	}
	// Soft exclusion is ignored when it would leave no address: the dial still
	// lands on the excluded address and the session works.
	conn, err := d.Dial(context.Background(), "127.0.0.1", nil, map[netipAddr]bool{mustAddr("127.0.0.1"): true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.Addr != mustAddr("127.0.0.1") || conn.Port != edge.Port() {
		t.Fatalf("soft-excluded fallback: %v:%d", conn.Addr, conn.Port)
	}
	serveSession(t, conn, http.NotFoundHandler())
	if s := edge.WaitSession(t); s.HelloErr != nil || s.Hello.StatusCode != 200 {
		t.Fatalf("hello on the soft-excluded address: %v", s.HelloErr)
	}
}

func TestSpreadKeepsIPv6First(t *testing.T) {
	addrs := []netip.Addr{mustAddr("2001:db8::1"), mustAddr("10.0.0.1"), mustAddr("2001:db8::2"), mustAddr("10.0.0.2")}
	got := spread(addrs, 1)
	want := []netip.Addr{mustAddr("2001:db8::2"), mustAddr("10.0.0.2"), mustAddr("2001:db8::1"), mustAddr("10.0.0.1")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("spread: %v", got)
	}
	if !reflect.DeepEqual(spread(addrs, 0), addrs) || !reflect.DeepEqual(spread(addrs[:1], 3), addrs[:1]) {
		t.Fatal("slot 0 and single-address lists are unchanged")
	}
}

func TestPrimaryFailureOnlyOnPrimaryPort(t *testing.T) {
	ca := testpki.NewCA(t)
	nginx := testedge.New(t, ca, "bnk", true)
	dead := deadPort(t)
	d := newDialer(t, ca, newCreds(t, ca, "127.0.0.1"), []int{dead, nginx.Port()}, nginx.Port())
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	d.Ports.now = func() time.Time { return now }
	// Primary fails, fallback works: the fallback is remembered, the primary test clock starts.
	c, err := d.Dial(context.Background(), "127.0.0.1", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	t0 := d.Ports.entries["127.0.0.1"].lastPrimaryT
	// Order is now [fallback, primary]. A non-network refusal on the fallback
	// ends the dial before the primary is tried: the primary clock must not move.
	now = now.Add(PrimaryRetestMin / 2)
	nginx.RejectAll = true
	if _, err := d.Dial(context.Background(), "127.0.0.1", nil, nil); !errors.Is(err, ErrNotNetwork) {
		t.Fatalf("expected the upgrade refusal, got %v", err)
	}
	if got := d.Ports.entries["127.0.0.1"].lastPrimaryT; !got.Equal(t0) {
		t.Fatalf("primary failure recorded for a fallback-port failure: %v (want %v)", got, t0)
	}
}

// After a drain the primary is retried through the restart gap; the refusals are
// not primary-port failures. Past the deadline the fallback applies as usual.
func TestDialAfterDrainRetriesPrimaryThroughTheGap(t *testing.T) {
	ca := testpki.NewCA(t)
	nginx := testedge.New(t, ca, "bnk", true)
	edge := testedge.New(t, ca, "bnk", false)
	d := newDialer(t, ca, newCreds(t, ca, "127.0.0.1"), []int{edge.Port(), nginx.Port()}, nginx.Port())
	addrs := []netip.Addr{mustAddr("127.0.0.1")}

	// Gap shorter than the window: the dial lands on the primary once it is back.
	go edge.RestartListener(t, 400*time.Millisecond)
	time.Sleep(50 * time.Millisecond) // the listener is closed now
	start := time.Now()
	c, err := d.DialAfterDrain(context.Background(), "127.0.0.1", addrs, addrs, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if c.Port != edge.Port() || c.Transport != proto.TransportDirect {
		t.Fatalf("expected the primary after the gap, got port %d transport %s", c.Port, c.Transport)
	}
	if time.Since(start) < 300*time.Millisecond {
		t.Fatalf("dial returned before the listener was back (%v)", time.Since(start))
	}
	if e := d.Ports.entries["127.0.0.1"]; e == nil || e.primaryDown {
		t.Fatalf("refusals inside the drain window must not mark the primary down: %+v", e)
	}

	// Gap longer than the window: the fallback is taken at the deadline and recorded.
	edge.CloseListener()
	start = time.Now()
	c, err = d.DialAfterDrain(context.Background(), "127.0.0.1", addrs, addrs, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if c.Transport != proto.TransportFallback {
		t.Fatalf("expected the fallback past the deadline, got %s", c.Transport)
	}
	if time.Since(start) < 500*time.Millisecond {
		t.Fatalf("fallback taken before the deadline (%v)", time.Since(start))
	}
	if o := d.Ports.Order("127.0.0.1"); o[0] != nginx.Port() {
		t.Fatalf("a primary still down at the deadline is a real failure: %v", o)
	}
}

func TestDialAPIReportsFailedAddresses(t *testing.T) {
	d := &Dialer{ConnectTimeout: time.Second, Log: slog.Default()}
	_, _, err := d.DialAPI(context.Background(), "127.0.0.1", deadPort(t))
	var ae *AddrError
	if !errors.As(err, &ae) || len(ae.Failed) != 1 || ae.Failed[0] != mustAddr("127.0.0.1") || len(ae.Resolved) != 1 {
		t.Fatalf("a refused connect must name the failed address: %v", err)
	}
}

func TestDiscoveryPopsProbeWhoami(t *testing.T) {
	ca := testpki.NewCA(t)
	edge := testedge.New(t, ca, "bnk", false)
	edge.Pops = []testedge.Pop{
		{Code: "bnk", Endpoint: "127.0.0.1", Ports: []int{edge.Port()}, Region: "eu-north", Allowed: true},
		{Code: "mum", Endpoint: "mum.tunnel.invalid", Region: "ap-south", Allowed: false},
	}
	edge.Pinned = []string{"bnk"}
	cs := newCreds(t, ca, "127.0.0.1")
	d := newDialer(t, ca, cs, []int{edge.Port()}, deadPort(t))
	disc := &Discovery{Dialer: d, Bootstrap: func() []string { return cs.Current().BootstrapEndpoints }}
	r, err := disc.Pops(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if r.Gen != 41 || len(r.Pops) != 2 || !r.IsPinned("bnk") || r.Source != "127.0.0.1" {
		t.Fatalf("pops: %+v", r)
	}
	// Cached: no second fetch, same pointer.
	if r2, _ := disc.Pops(context.Background(), false); r2 != r {
		t.Fatal("expected the cached pop list")
	}
	pr := disc.Probe(context.Background(), []Pop{r.Pops[0]})
	if len(pr) != 1 || pr[0].Err != nil || pr[0].RTT <= 0 || len(pr[0].Samples) != 3 || pr[0].Port != edge.Port() {
		t.Fatalf("probe: %+v", pr)
	}
	w, ep, err := disc.Whoami(context.Background(), "")
	if err != nil || w.Pop != "bnk" || ep != "127.0.0.1" {
		t.Fatalf("whoami: %v %+v", err, w)
	}
	if alpns := edge.OfferedALPNs(); len(alpns) == 0 || alpns[0][0] != proto.ALPNAPI {
		t.Fatalf("discovery must use ALPN %s, saw %v", proto.ALPNAPI, alpns)
	}
}

func TestDiscoveryFailureModes(t *testing.T) {
	ca := testpki.NewCA(t)
	edge := testedge.New(t, ca, "bnk", false)
	cs := newCreds(t, ca, "dead.test", "127.0.0.1")
	d := newDialer(t, ca, cs, []int{edge.Port()}, deadPort(t))
	d.Resolver = testedge.StaticResolver{} // dead.test does not resolve; 127.0.0.1 is a literal
	disc := &Discovery{Dialer: d, Bootstrap: func() []string { return cs.Current().BootstrapEndpoints }}

	// One bootstrap endpoint dead: the other one is used.
	r, err := disc.Pops(context.Background(), false)
	if err != nil || r.Source != "127.0.0.1" {
		t.Fatalf("dead bootstrap must be skipped: %v %+v", err, r)
	}
	if _, ep, err := disc.Whoami(context.Background(), ""); err != nil || ep != "127.0.0.1" {
		t.Fatalf("whoami via the live endpoint: %v %s", err, ep)
	}

	cases := map[string]func(*testedge.Edge){
		"429":          func(e *testedge.Edge) { e.APIStatus = 429 },
		"invalid json": func(e *testedge.Edge) { e.PopsRaw = []byte("{not json") },
		"duplicate codes": func(e *testedge.Edge) {
			e.Pops = []testedge.Pop{{Code: "bnk", Endpoint: "a.test", Allowed: true}, {Code: "BNK", Endpoint: "b.test", Allowed: true}}
		},
		"empty list": func(e *testedge.Edge) { e.Pops = []testedge.Pop{}; e.PopsRaw = []byte(`{"gen":1,"pops":[]}`) },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			e := testedge.New(t, ca, "bnk", false)
			setup(e)
			cs := newCreds(t, ca, "127.0.0.1")
			d := newDialer(t, ca, cs, []int{e.Port()}, deadPort(t))
			disc := &Discovery{Dialer: d, Bootstrap: func() []string { return cs.Current().BootstrapEndpoints }}
			if _, err := disc.Pops(context.Background(), false); err == nil {
				t.Fatal("expected an error")
			} else if !errors.Is(err, ErrNotNetwork) && name != "duplicate codes" && name != "empty list" {
				t.Fatalf("an API-level failure must not be treated as a network failure: %v", err)
			}
			if disc.Cached() != nil {
				t.Fatal("a failed fetch must not populate the cache")
			}
		})
	}
}

func TestDiscoveryOver443(t *testing.T) {
	ca := testpki.NewCA(t)
	nginx := testedge.New(t, ca, "bnk", true)
	cs := newCreds(t, ca, "127.0.0.1")
	d := newDialer(t, ca, cs, []int{deadPort(t), nginx.Port()}, nginx.Port())
	disc := &Discovery{Dialer: d, Bootstrap: func() []string { return cs.Current().BootstrapEndpoints }}
	r, err := disc.Pops(context.Background(), false)
	if err != nil || len(r.Pops) != 1 {
		t.Fatalf("pops over 443: %v %+v", err, r)
	}
	pr := disc.Probe(context.Background(), r.Pops)
	if pr[0].Err != nil || pr[0].Port != nginx.Port() {
		t.Fatalf("probe over 443: %+v", pr[0])
	}
	for _, a := range nginx.OfferedALPNs() {
		if !reflect.DeepEqual(a, []string{proto.ALPNHTTP1}) {
			t.Fatalf("443 discovery must offer http/1.1 only, saw %v", a)
		}
	}
}
