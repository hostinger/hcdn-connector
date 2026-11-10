package connector

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hostinger/hcdn-connector/internal/proto"
	"github.com/hostinger/hcdn-connector/internal/testedge"
	"github.com/hostinger/hcdn-connector/internal/testpki"
	"github.com/hostinger/hcdn-connector/pkg/creds"
	"github.com/hostinger/hcdn-connector/pkg/localguard"
)

func TestWhoamiQuick(t *testing.T) {
	ca := testpki.NewCA(t)
	edge := testedge.New(t, ca, "bnk", false)
	edge.SetQuickZone("hostingersite.dev")
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, ca.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := creds.NewQuick([]string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s, err := creds.NewMemoryStore(c, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	w, err := Whoami(context.Background(), WhoamiOptions{Credentials: s, Ports: []int{edge.Port()}, ServerCAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	if w.Class != ClassQuick || w.TunnelID != c.TunnelID || w.Hostname != creds.QuickHostname(c.TunnelID, "hostingersite.dev") {
		t.Fatalf("whoami %+v", w)
	}
	if !w.ExpiresAt.Equal(c.Leaf.NotAfter) {
		t.Fatalf("expires_at %s, want %s", w.ExpiresAt, c.Leaf.NotAfter)
	}

	if _, err := Whoami(context.Background(), WhoamiOptions{}); err == nil {
		t.Fatal("Credentials is required")
	}
}

const quickZone = "hostingerpreview.dev"

type quickResult struct {
	expired bool
	err     error
}

type quickRun struct {
	edge   *testedge.Edge
	ready  chan QuickTunnel
	reach  chan QuickTunnel
	pause  chan QuickPause
	done   chan quickResult
	cancel context.CancelFunc
}

// quickOpts points RunQuick at edge; o.URL "" gets a dead service.
func quickOpts(t *testing.T, ca *testpki.CA, port int, o QuickOptions) QuickOptions {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, ca.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if o.URL == "" {
		o.URL = "http://127.0.0.1:1"
	}
	o.Bootstrap, o.Ports, o.ServerCAFile, o.Version = []string{"127.0.0.1"}, []int{port}, caFile, "hostinger-cli/test"
	return o
}

// startRunQuick runs RunQuick against a fake quick edge in the given owner
// mode; setup changes the edge before the connector dials.
func startRunQuick(t *testing.T, mode string, o QuickOptions, setup ...func(*testedge.Edge)) *quickRun {
	t.Helper()
	ca := testpki.NewCA(t)
	r := &quickRun{edge: testedge.New(t, ca, "bnk", false), ready: make(chan QuickTunnel, 1),
		reach: make(chan QuickTunnel, 1), pause: make(chan QuickPause, 8), done: make(chan quickResult, 1)}
	r.edge.SetQuickZone(quickZone)
	r.edge.OwnerMode, r.edge.OwnerIssuer = mode, "wh-api-test"
	for _, f := range setup {
		f(r.edge)
	}
	o = quickOpts(t, ca, r.edge.Port(), o)
	o.OnReady = func(q QuickTunnel) { r.ready <- q }
	o.OnReachable = func(q QuickTunnel) { r.reach <- q }
	o.OnPause = func(p QuickPause) { r.pause <- p }
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() {
		expired, err := RunQuick(ctx, o)
		r.done <- quickResult{expired, err}
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case res := <-r.done:
			r.done <- res
		case <-time.After(20 * time.Second):
			t.Error("RunQuick did not return")
		}
	})
	return r
}

func (r *quickRun) wait(t *testing.T) quickResult {
	t.Helper()
	select {
	case res := <-r.done:
		r.done <- res // for the cleanup
		return res
	case <-time.After(20 * time.Second):
		t.Fatal("RunQuick did not return")
		return quickResult{}
	}
}

func (r *quickRun) waitReady(t *testing.T) QuickTunnel {
	t.Helper()
	select {
	case q := <-r.ready:
		return q
	case res := <-r.done:
		t.Fatalf("RunQuick returned before OnReady: %+v", res)
	case <-time.After(10 * time.Second):
		t.Fatal("no OnReady")
	}
	return QuickTunnel{}
}

func TestDefaultQuickBootstrap(t *testing.T) {
	b := DefaultQuickBootstrap()
	if len(b) != 1 || b[0] != "tunnel.hostinger.io" {
		t.Fatalf("%q", b)
	}
	b[0] = "changed"
	if DefaultQuickBootstrap()[0] != "tunnel.hostinger.io" {
		t.Fatal("DefaultQuickBootstrap must return a new slice")
	}
}

func TestRunQuickReadyAndCancel(t *testing.T) {
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "host="+r.Host) }))
	defer svc.Close()
	start := time.Now()
	r := startRunQuick(t, "", QuickOptions{URL: svc.URL, HostHeader: "localhost"})
	q := r.waitReady(t)
	if q.Hostname != creds.QuickHostname(q.TunnelID, quickZone) || q.URL != "https://"+q.Hostname {
		t.Fatalf("ready %+v", q)
	}
	if q.ExpiresAt.Before(start.Add(23*time.Hour)) || q.ExpiresAt.After(start.Add(24*time.Hour)) {
		t.Fatalf("expires_at %s", q.ExpiresAt)
	}
	if q.Owner.Mode != "" || q.Owner.Absent != OwnerAbsentNotRequested || q.Owner.Linked() {
		t.Fatalf("owner %+v", q.Owner)
	}
	s := r.edge.WaitSession(t)
	if s.HelloErr != nil {
		t.Fatalf("hello: %v", s.HelloErr)
	}
	if v := s.Hello.Header.Get(proto.HdrOwnerAbsent); v != OwnerAbsentNotRequested {
		t.Fatalf("hcdn-owner-absent %q", v)
	}
	res := s.Get(t, q.Hostname, "/")
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(body) != "host=localhost" {
		t.Fatalf("got %d %q", res.StatusCode, body)
	}
	if v := s.Hello.Header.Get(proto.HdrConnVersion); v != "hostinger-cli/test" {
		t.Fatalf("hello version %q", v)
	}
	if h := r.edge.WhoamiHeaders(); len(h) != 1 || h[0].Get("User-Agent") != "hcdn-connector/hostinger-cli/test" {
		t.Fatalf("whoami headers %v", h)
	}
	r.cancel()
	if got := r.wait(t); got.expired || got.err != nil {
		t.Fatalf("cancel: %+v", got)
	}
}

func TestRunQuickOwner(t *testing.T) {
	ticket := loadOwnerVectors(t).Valid[0].Ticket
	t.Run("linked", func(t *testing.T) {
		r := startRunQuick(t, OwnerModeLog, QuickOptions{Owner: func(context.Context, string, time.Time) (string, error) {
			return ticket, nil
		}})
		q := r.waitReady(t)
		if !q.Owner.Linked() || q.Owner.Ticket != ticket || q.Owner.ClientID != "123456" || q.Owner.Mode != OwnerModeLog {
			t.Fatalf("owner %+v", q.Owner)
		}
		if s := r.edge.WaitSession(t); s.HelloErr != nil || s.Hello.Header.Get(proto.HdrOwnerTicket) != ticket {
			t.Fatalf("hello: %v %v", s.HelloErr, s.Hello.Header)
		}
	})
	t.Run("not linked", func(t *testing.T) {
		r := startRunQuick(t, OwnerModeLog, QuickOptions{})
		q := r.waitReady(t)
		if q.Owner.Linked() || q.Owner.Absent != OwnerAbsentUnsupported || q.Owner.Mode != OwnerModeLog {
			t.Fatalf("owner %+v", q.Owner)
		}
	})
	t.Run("require without ticket", func(t *testing.T) {
		r := startRunQuick(t, OwnerModeRequire, QuickOptions{})
		res := r.wait(t)
		var qe *QuickError
		var ee *ExitError
		if !errors.Is(res.err, ErrOwnerRequired) || !errors.As(res.err, &qe) || qe.Kind != ErrOwnerRequired ||
			qe.Owner.Absent != OwnerAbsentUnsupported || errors.As(res.err, &ee) || res.expired {
			t.Fatalf("%+v", res)
		}
		if len(r.ready) != 0 || r.edge.Dials.Load() != 0 {
			t.Fatalf("no OnReady and no session: ready %d dials %d", len(r.ready), r.edge.Dials.Load())
		}
	})
}

func TestRunQuickGoaway(t *testing.T) {
	for _, tc := range []struct {
		reason string
		kind   error
		code   int
	}{
		{proto.ReasonRevoked, ErrTakenDown, 78},
		{proto.ReasonUnknownSerial, ErrCertRejected, 78},
		{proto.ReasonOwnerRequired, ErrOwnerRequired, 77},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			r := startRunQuick(t, "", QuickOptions{})
			r.waitReady(t)
			s := r.edge.WaitSession(t)
			if s.HelloErr != nil {
				t.Fatal(s.HelloErr)
			}
			s.Goaway(t, tc.reason, 0)
			res := r.wait(t)
			var qe *QuickError
			var ee *ExitError
			if !errors.As(res.err, &qe) || qe.Kind != tc.kind || !errors.Is(res.err, tc.kind) ||
				!errors.As(res.err, &ee) || ee.Code != tc.code || ee.Reason != tc.reason {
				t.Fatalf("%+v", res)
			}
			for _, other := range []error{ErrTakenDown, ErrCertRejected, ErrOwnerRequired} {
				if other != tc.kind && errors.Is(res.err, other) {
					t.Fatalf("%v must not match %v", res.err, other)
				}
			}
		})
	}
}

func TestRunQuickExpires(t *testing.T) {
	prev := quickStopAt
	quickStopAt = func(time.Time) time.Time { return time.Now().Add(2 * time.Second) }
	t.Cleanup(func() { quickStopAt = prev })
	r := startRunQuick(t, "", QuickOptions{})
	r.waitReady(t)
	if res := r.wait(t); !res.expired || res.err != nil {
		t.Fatalf("expiry: %+v", res)
	}
}

func TestRunQuickCapExceeded(t *testing.T) {
	r := startRunQuick(t, "", QuickOptions{})
	r.waitReady(t)
	s := r.edge.WaitSession(t)
	if s.HelloErr != nil {
		t.Fatal(s.HelloErr)
	}
	s.Goaway(t, proto.ReasonCapExceeded, 30)
	select {
	case p := <-r.pause:
		if p.Reason != PauseCapExceeded || time.Until(p.RetryAt) < 20*time.Second || time.Until(p.RetryAt) > 31*time.Second {
			t.Fatalf("pause %+v", p)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no OnPause")
	}
	time.Sleep(1500 * time.Millisecond) // one more tick: the same pause is not reported again
	if len(r.pause) != 0 {
		t.Fatalf("pause reported twice: %d more", len(r.pause))
	}
	r.cancel()
	if res := r.wait(t); res.expired || res.err != nil {
		t.Fatalf("cancel: %+v", res)
	}
}

func TestRunQuickStartErrors(t *testing.T) {
	ca := testpki.NewCA(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	_, err = RunQuick(context.Background(), quickOpts(t, ca, closedPort, QuickOptions{}))
	if !errors.Is(err, ErrEdgeUnreachable) {
		t.Fatalf("closed port: %v", err)
	}
	var op *net.OpError
	if !errors.As(err, &op) || !strings.Contains(err.Error(), ErrEdgeUnreachable.Error()) {
		t.Fatalf("the dial error must stay reachable: %v", err)
	}

	// No QuickZone: like tunneld < 0.3.0, the handshake refuses the self-signed leaf.
	edge := testedge.New(t, ca, "bnk", false)
	if _, err := RunQuick(context.Background(), quickOpts(t, ca, edge.Port(), QuickOptions{})); !errors.Is(err, ErrQuickRefused) {
		t.Fatalf("no quick zone: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if expired, err := RunQuick(ctx, quickOpts(t, ca, closedPort, QuickOptions{})); expired || err != nil {
		t.Fatalf("cancelled before whoami: %v %v", expired, err)
	}

	var qe *QuickError
	if _, err := RunQuick(context.Background(), QuickOptions{}); err == nil || errors.As(err, &qe) {
		t.Fatalf("URL is required: %v", err)
	}
}

func TestQuickErrorText(t *testing.T) {
	cause := errors.New("dial tcp 127.0.0.1:1: connection refused")
	if got := (&QuickError{Kind: ErrEdgeUnreachable, Err: cause}).Error(); got != ErrEdgeUnreachable.Error()+": "+cause.Error() {
		t.Fatal(got)
	}
	wrapped := errors.Join(ErrOwnerRequired)
	if got := (&QuickError{Kind: ErrOwnerRequired, Err: wrapped}).Error(); got != ErrOwnerRequired.Error() {
		t.Fatalf("no repeated prefix: %q", got)
	}
	if got := (&QuickError{Kind: ErrTakenDown}).Error(); got != ErrTakenDown.Error() {
		t.Fatal(got)
	}
}

// A URL that reaches a sensitive local port is refused before any edge call:
// the edge port is closed, so reaching it would be ErrEdgeUnreachable.
func TestRunQuickRefusesBlockedLocalPorts(t *testing.T) {
	ca := testpki.NewCA(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	for _, u := range []string{"http://0:22", "http://127.1:9229", "http://0x7f000001:6379", "http://[::ffff:127.0.0.1]:3306", "http://localhost.:6060"} {
		_, err := RunQuick(context.Background(), quickOpts(t, ca, closedPort, QuickOptions{URL: u}))
		var be *localguard.BlockedError
		if !errors.As(err, &be) || !errors.Is(err, localguard.ErrBlocked) {
			t.Errorf("%s: err = %v, want a *localguard.BlockedError", u, err)
		}
	}
	// Jupyter's port is warn only: the run goes on to the edge.
	if _, err := RunQuick(context.Background(), quickOpts(t, ca, closedPort, QuickOptions{URL: "http://localhost:8888"})); !errors.Is(err, ErrEdgeUnreachable) {
		t.Errorf("8888: err = %v, want the edge dial", err)
	}
}

// A name that resolves to loopback is refused too. localtest.me needs DNS.
func TestRunQuickRefusesALoopbackName(t *testing.T) {
	ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip4", "localtest.me")
	if err != nil || len(ips) == 0 || !ips[0].IsLoopback() {
		t.Skipf("localtest.me does not resolve to loopback here: %v %v", ips, err)
	}
	_, err = RunQuick(context.Background(), QuickOptions{URL: "http://localtest.me:6379", Bootstrap: []string{"127.0.0.1"}, Ports: []int{1}})
	if !errors.Is(err, localguard.ErrBlocked) {
		t.Fatalf("err = %v, want ErrBlocked", err)
	}
}

// expectNoReady fails when OnReady runs within d.
func (r *quickRun) expectNoReady(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case q := <-r.ready:
		t.Fatalf("OnReady too early: %+v", q)
	case res := <-r.done:
		t.Fatalf("RunQuick returned: %+v", res)
	case <-time.After(d):
	}
}

func withFeatures(f string) func(*testedge.Edge) {
	return func(e *testedge.Edge) { e.EdgeFeatures = f }
}

func withHelloGate(gate chan struct{}) func(*testedge.Edge) {
	return func(e *testedge.Edge) { e.SetHelloGate(gate) }
}

func withNoHello(e *testedge.Edge) { e.NoHello = true }

func TestRunQuickReadyWaitsForHello(t *testing.T) {
	gate := make(chan struct{})
	r := startRunQuick(t, "", QuickOptions{}, withHelloGate(gate))
	r.expectNoReady(t, 500*time.Millisecond)
	if r.edge.Dials.Load() == 0 {
		t.Fatal("no session dialed")
	}
	released := time.Now()
	close(gate)
	q := r.waitReady(t)
	if !q.Reachable || q.Scope != ScopeSession || q.Pop != "bnk" {
		t.Fatalf("ready %+v", q)
	}
	if time.Since(released) > 5*time.Second {
		t.Fatal("OnReady long after the hello")
	}
}

func TestRunQuickVisiblePop(t *testing.T) {
	r := startRunQuick(t, "", QuickOptions{VisibleWait: 10 * time.Second}, withFeatures("ws, Visible"))
	s := r.edge.WaitSession(t)
	if s.HelloErr != nil {
		t.Fatal(s.HelloErr)
	}
	r.expectNoReady(t, 200*time.Millisecond)
	if code := s.Visible(t, ScopePop); code != http.StatusNoContent {
		t.Fatalf("visible status %d", code)
	}
	q := r.waitReady(t)
	if !q.Reachable || q.Scope != ScopePop || q.Pop != "bnk" {
		t.Fatalf("ready %+v", q)
	}
}

func TestRunQuickVisibleWaitRunsOut(t *testing.T) {
	r := startRunQuick(t, "", QuickOptions{VisibleWait: 400 * time.Millisecond}, withFeatures("visible"))
	s := r.edge.WaitSession(t)
	if s.HelloErr != nil {
		t.Fatal(s.HelloErr)
	}
	helloAt := time.Now()
	q := r.waitReady(t)
	if !q.Reachable || q.Scope != ScopeSession {
		t.Fatalf("ready %+v", q)
	}
	if d := time.Since(helloAt); d < 300*time.Millisecond {
		t.Fatalf("OnReady %s after the hello, before VisibleWait", d)
	}
}

func TestRunQuickEdgeWithoutVisible(t *testing.T) {
	r := startRunQuick(t, "", QuickOptions{VisibleWait: 10 * time.Second})
	s := r.edge.WaitSession(t)
	if s.HelloErr != nil {
		t.Fatal(s.HelloErr)
	}
	helloAt := time.Now()
	q := r.waitReady(t)
	if !q.Reachable || q.Scope != ScopeSession || q.Pop != "bnk" {
		t.Fatalf("ready %+v", q)
	}
	if d := time.Since(helloAt); d > 3*time.Second {
		t.Fatalf("OnReady waited %s for an edge without the feature", d)
	}
}

func TestRunQuickReadyTimeoutThenReachable(t *testing.T) {
	gate := make(chan struct{})
	r := startRunQuick(t, "", QuickOptions{ReadyTimeout: 300 * time.Millisecond}, withHelloGate(gate))
	q := r.waitReady(t)
	if q.Reachable || q.Scope != "" || q.Pop != "" || q.URL == "" {
		t.Fatalf("ready %+v", q)
	}
	select {
	case q := <-r.reach:
		t.Fatalf("OnReachable before any hello: %+v", q)
	case <-time.After(200 * time.Millisecond):
	}
	close(gate)
	select {
	case q := <-r.reach:
		if !q.Reachable || q.Scope != ScopeSession || q.URL == "" {
			t.Fatalf("reachable %+v", q)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no OnReachable")
	}
	select {
	case q := <-r.ready:
		t.Fatalf("OnReady twice: %+v", q)
	default:
	}
}

func TestRunQuickLegacyEarlyReady(t *testing.T) {
	gate := make(chan struct{})
	r := startRunQuick(t, "", QuickOptions{ReadyTimeout: -1}, withHelloGate(gate))
	if q := r.waitReady(t); q.Reachable {
		t.Fatalf("ready %+v", q)
	}
	close(gate)
	select {
	case q := <-r.reach:
		if !q.Reachable || q.Scope != ScopeSession {
			t.Fatalf("reachable %+v", q)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no OnReachable")
	}
}

func TestRunQuickRevokedBeforeReady(t *testing.T) {
	r := startRunQuick(t, "", QuickOptions{}, withNoHello)
	s := r.edge.WaitSession(t)
	s.Goaway(t, proto.ReasonRevoked, 0)
	res := r.wait(t)
	var ee *ExitError
	if !errors.Is(res.err, ErrTakenDown) || !errors.As(res.err, &ee) || ee.Code != 78 || res.expired {
		t.Fatalf("%+v", res)
	}
	if len(r.ready) != 0 || len(r.reach) != 0 {
		t.Fatal("OnReady after a revoked run")
	}
}

func TestRunQuickPauseBeforeReady(t *testing.T) {
	r := startRunQuick(t, "", QuickOptions{ReadyTimeout: 4 * time.Second}, withNoHello)
	s := r.edge.WaitSession(t)
	s.Goaway(t, proto.ReasonCapExceeded, 30)
	select {
	case p := <-r.pause:
		if p.Reason != PauseCapExceeded {
			t.Fatalf("pause %+v", p)
		}
	case q := <-r.ready:
		t.Fatalf("OnReady before OnPause: %+v", q)
	case <-time.After(10 * time.Second):
		t.Fatal("no OnPause")
	}
	if q := r.waitReady(t); q.Reachable {
		t.Fatalf("ready %+v", q)
	}
	r.cancel()
	if res := r.wait(t); res.expired || res.err != nil {
		t.Fatalf("cancel: %+v", res)
	}
}
