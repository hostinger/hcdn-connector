package session

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/hostinger/hcdn-connector/internal/h2srv"
	"github.com/hostinger/hcdn-connector/internal/metrics"
	"github.com/hostinger/hcdn-connector/internal/proto"
	"github.com/hostinger/hcdn-connector/internal/testedge"
	"github.com/hostinger/hcdn-connector/internal/testpki"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type supRig struct {
	sup   *Supervisor
	edge  *testedge.Edge
	mets  *metrics.Metrics
	clock *fakeClock
}

// newSupRig starts a supervisor against one fake edge. dual adds ::1 as a
// second address of the endpoint (skips the test when IPv6 loopback is absent).
func newSupRig(t *testing.T, target int, dual bool, helloTimeout time.Duration) *supRig {
	t.Helper()
	ca := testpki.NewCA(t)
	edge := testedge.New(t, ca, "bnk", false, "dual.test")
	endpoint := "127.0.0.1"
	d := newDialer(t, ca, newCreds(t, ca, "127.0.0.1"), []int{edge.Port()}, deadPort(t))
	if dual {
		if !edge.ListenAlso(t, "::1") {
			t.Skip("IPv6 loopback not available")
		}
		endpoint = "dual.test"
		d.Resolver = testedge.StaticResolver{"dual.test": {"127.0.0.1", "::1"}}
	}
	mets := metrics.New()
	opts := func(_ *Supervisor, _ int, conn *Conn) h2srv.Options {
		return h2srv.Options{Handler: http.NotFoundHandler(), Version: "0.1.0-test", ConnectorID: "cid",
			Transport: conn.Transport, HelloTimeout: helloTimeout}
	}
	sup := NewSupervisor("bnk", endpoint, "eu", false, target, d, opts, mets, slog.Default(), nil)
	clock := &fakeClock{t: time.Now()}
	sup.now = clock.now
	for _, sl := range sup.slots {
		sl.backoff.rnd = func() float64 { return 0 } // no jitter waits in tests
	}
	return &supRig{sup: sup, edge: edge, mets: mets, clock: clock}
}

func (r *supRig) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r.sup.Start(ctx)
	t.Cleanup(func() { cancel(); r.sup.Stop() })
}

func addrsOf(sup *Supervisor) []string {
	var out []string
	for _, si := range sup.Snapshot().Sessions {
		if si.State == StateReady {
			out = append(out, si.Addr)
		}
	}
	return out
}

func TestSupervisorDrainReplacesBeforeOldSessionCloses(t *testing.T) {
	r := newSupRig(t, 1, false, 0)
	r.start(t)
	s1 := r.edge.WaitSession(t)
	if s1.HelloErr != nil {
		t.Fatal(s1.HelloErr)
	}
	waitCond(t, func() bool { return r.sup.ReadyCount() == 1 })

	// The fake edge keeps the drained connection open (tunneld would finish streams first).
	s1.Goaway(t, proto.ReasonDrain, 0)
	s2 := r.edge.WaitSession(t)
	if s2.HelloErr != nil {
		t.Fatalf("replacement dial: %v", s2.HelloErr)
	}
	if res := s1.Get(t, "x.example", "/"); res.StatusCode != 404 {
		t.Fatalf("old session must keep serving while draining: %d", res.StatusCode)
	}
	waitCond(t, func() bool { snap := r.sup.Snapshot(); return snap.Ready == 1 && snap.Draining == 1 })
	if got := testutil.ToFloat64(r.mets.Sessions.WithLabelValues("bnk", string(StateDraining))); got != 1 {
		t.Fatalf("draining gauge %v", got)
	}
	s1.CC.Close()
	waitCond(t, func() bool { return r.sup.Snapshot().Draining == 0 })
	if got := testutil.ToFloat64(r.mets.Reconnects.WithLabelValues("goaway_drain")); got != 1 {
		t.Fatalf("reconnects{goaway_drain} = %v", got)
	}
}

func TestSupervisorSpreadsAcrossAddresses(t *testing.T) {
	r := newSupRig(t, 2, true, 0)
	r.start(t)
	r.edge.WaitSession(t)
	r.edge.WaitSession(t)
	waitCond(t, func() bool { return r.sup.ReadyCount() == 2 })
	a := addrsOf(r.sup)
	if len(a) != 2 || a[0] == a[1] {
		t.Fatalf("sessions must use distinct addresses: %v", a)
	}
}

func TestSupervisorDrainAvoidsSameAddress(t *testing.T) {
	r := newSupRig(t, 1, true, 0)
	r.start(t)
	s1 := r.edge.WaitSession(t)
	if s1.HelloErr != nil {
		t.Fatal(s1.HelloErr)
	}
	waitCond(t, func() bool { return r.sup.ReadyCount() == 1 })
	first := addrsOf(r.sup)[0]
	s1.Goaway(t, proto.ReasonDrain, 0)
	s2 := r.edge.WaitSession(t)
	if s2.HelloErr != nil {
		t.Fatal(s2.HelloErr)
	}
	waitCond(t, func() bool { a := addrsOf(r.sup); return len(a) == 1 && a[0] != first })
	s1.CC.Close()
}

// Regression: a `drain` announces a tunneld restart. The
// redial must ride through the listener gap on the primary port instead of taking the
// 443 fallback and parking the endpoint there.
func TestSupervisorDrainRedialSurvivesRestartGap(t *testing.T) {
	ca := testpki.NewCA(t)
	edge := testedge.New(t, ca, "bnk", false)
	nginx := testedge.New(t, ca, "bnk", true)
	d := newDialer(t, ca, newCreds(t, ca, "127.0.0.1"), []int{edge.Port(), nginx.Port()}, nginx.Port())
	opts := func(_ *Supervisor, _ int, conn *Conn) h2srv.Options {
		return h2srv.Options{Handler: http.NotFoundHandler(), Version: "0.1.0-test", ConnectorID: "cid", Transport: conn.Transport}
	}
	sup := NewSupervisor("bnk", "127.0.0.1", "eu", false, 1, d, opts, metrics.New(), slog.Default(), nil)
	clock := &fakeClock{t: time.Now()}
	sup.now = clock.now
	r := &supRig{sup: sup, edge: edge, clock: clock}
	r.start(t)
	s1 := edge.WaitSession(t)
	if s1.HelloErr != nil {
		t.Fatal(s1.HelloErr)
	}
	waitCond(t, func() bool { return sup.ReadyCount() == 1 })
	// The drain guard treats a session younger than drainMinLife as a drain loop.
	clock.add(drainMinLife + time.Second)

	edge.CloseListener() // the old instance stops listening before it drains (systemd stop)
	s1.Goaway(t, proto.ReasonDrain, 0)
	edge.RestartListener(t, 400*time.Millisecond)

	s2 := edge.WaitSession(t)
	if s2.HelloErr != nil {
		t.Fatal(s2.HelloErr)
	}
	waitCond(t, func() bool {
		for _, si := range sup.Snapshot().Sessions {
			if si.State == StateReady && si.Port == edge.Port() && si.Transport == proto.TransportDirect {
				return true
			}
		}
		return false
	})
	if n := nginx.Dials.Load(); n != 0 {
		t.Fatalf("the redial took the 443 fallback %d time(s)", n)
	}
	if o := d.Ports.Order("127.0.0.1"); o[0] != edge.Port() {
		t.Fatalf("primary port must stay first after the restart gap: %v", o)
	}
	s1.CC.Close()
}

// A drain of a session on the 443 fallback (primary blocked) redials 443 at once
// instead of retrying the primary for DrainRetryWindow.
func TestSupervisorDrainFromFallbackSkipsDrainWindow(t *testing.T) {
	ca := testpki.NewCA(t)
	nginx := testedge.New(t, ca, "bnk", true)
	d := newDialer(t, ca, newCreds(t, ca, "127.0.0.1"), []int{deadPort(t), nginx.Port()}, nginx.Port())
	opts := func(_ *Supervisor, _ int, conn *Conn) h2srv.Options {
		return h2srv.Options{Handler: http.NotFoundHandler(), Version: "0.1.0-test", ConnectorID: "cid", Transport: conn.Transport}
	}
	sup := NewSupervisor("bnk", "127.0.0.1", "eu", false, 1, d, opts, metrics.New(), slog.Default(), nil)
	clock := &fakeClock{t: time.Now()}
	sup.now = clock.now
	r := &supRig{sup: sup, edge: nginx, clock: clock}
	r.start(t)
	s1 := nginx.WaitSession(t)
	if s1.HelloErr != nil {
		t.Fatal(s1.HelloErr)
	}
	waitCond(t, func() bool { return sup.ReadyCount() == 1 })
	clock.add(drainMinLife + time.Second)

	start := time.Now()
	s1.Goaway(t, proto.ReasonDrain, 0)
	s2 := nginx.WaitSession(t)
	if s2.HelloErr != nil {
		t.Fatal(s2.HelloErr)
	}
	if el := time.Since(start); el >= DrainRetryWindow/2 {
		t.Fatalf("redial from the fallback waited %v for the primary", el)
	}
	waitCond(t, func() bool {
		for _, si := range sup.Snapshot().Sessions {
			if si.State == StateReady && si.Transport == proto.TransportFallback {
				return true
			}
		}
		return false
	})
	s1.CC.Close()
}

func TestSupervisorBackoffResetsAfterStableSession(t *testing.T) {
	r := newSupRig(t, 1, false, 0)
	r.start(t)
	s1 := r.edge.WaitSession(t)
	if s1.HelloErr != nil {
		t.Fatal(s1.HelloErr)
	}
	waitCond(t, func() bool { return r.sup.ReadyCount() == 1 })
	sl := r.sup.slots[0]
	for i := 0; i < 3; i++ {
		sl.backoff.Next()
	}
	// Short-lived: no reset, the schedule advances.
	s1.CC.Close()
	s2 := r.edge.WaitSession(t)
	waitCond(t, func() bool { return r.sup.ReadyCount() == 1 })
	if sl.backoff.Attempt() != 4 {
		t.Fatalf("attempt after a short session = %d, want 4", sl.backoff.Attempt())
	}
	// Lived > 60 s: reset, then one step for the redial.
	r.clock.add(StableSession + time.Second)
	s2.CC.Close()
	r.edge.WaitSession(t)
	waitCond(t, func() bool { return r.sup.ReadyCount() == 1 })
	if sl.backoff.Attempt() != 1 {
		t.Fatalf("attempt after a stable session = %d, want 1", sl.backoff.Attempt())
	}
}

func TestSupervisorHelloTimeoutBacksOff(t *testing.T) {
	r := newSupRig(t, 1, false, 200*time.Millisecond)
	r.edge.NoHello = true
	r.start(t)
	r.edge.WaitSession(t)
	waitCond(t, func() bool {
		return testutil.ToFloat64(r.mets.Reconnects.WithLabelValues("hello_timeout")) >= 1
	})
	waitCond(t, func() bool { return r.edge.Dials.Load() >= 2 })
	if r.sup.slots[0].backoff.Attempt() < 1 {
		t.Fatal("hello timeout must advance the backoff")
	}
	if snap := r.sup.Snapshot(); snap.Ready != 0 {
		t.Fatalf("no session may be ready without hello: %+v", snap)
	}
}

func TestSupervisorRotateOneSlotAtATime(t *testing.T) {
	r := newSupRig(t, 2, false, 0)
	r.start(t)
	a, b := r.edge.WaitSession(t), r.edge.WaitSession(t)
	waitCond(t, func() bool { return r.sup.ReadyCount() == 2 })

	// Hold every new hello: the second slot must not drain while the first one's replacement waits.
	gate := make(chan struct{})
	r.edge.SetHelloGate(gate)
	done := make(chan struct{})
	go func() { r.sup.Rotate(context.Background()); close(done) }()
	closing := func(s *testedge.Session) bool { st := s.CC.State(); return st.Closing || st.Closed }
	waitCond(t, func() bool { return r.edge.Dials.Load() == 3 })
	time.Sleep(100 * time.Millisecond)
	if closing(a) == closing(b) {
		t.Fatalf("exactly one old session must drain while its replacement is not ready (a=%v b=%v)", closing(a), closing(b))
	}
	gate <- struct{}{}
	if s := r.edge.WaitSession(t); s.HelloErr != nil {
		t.Fatal(s.HelloErr)
	}
	waitCond(t, func() bool { return closing(a) && closing(b) && r.edge.Dials.Load() == 4 })
	gate <- struct{}{}
	if s := r.edge.WaitSession(t); s.HelloErr != nil {
		t.Fatal(s.HelloErr)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("rotate did not finish")
	}
	waitCond(t, func() bool { return r.sup.ReadyCount() == 2 })
}

func TestSupervisorRotateStopsWhenReplacementNotReady(t *testing.T) {
	r := newSupRig(t, 2, false, 0)
	r.start(t)
	a, b := r.edge.WaitSession(t), r.edge.WaitSession(t)
	waitCond(t, func() bool { return r.sup.ReadyCount() == 2 })

	// The edge never answers hello on a new session (e.g. it rejects the new certificate).
	gate := make(chan struct{})
	t.Cleanup(func() { close(gate) })
	r.edge.SetHelloGate(gate)
	r.sup.readyWait = 300 * time.Millisecond
	if r.sup.Rotate(context.Background()) {
		t.Fatal("rotate must report that the replacement did not become ready")
	}
	closing := func(s *testedge.Session) bool { st := s.CC.State(); return st.Closing || st.Closed }
	if closing(a) == closing(b) {
		t.Fatalf("exactly one old session may drain (a=%v b=%v)", closing(a), closing(b))
	}
	if r.sup.ReadyCount() != 1 {
		t.Fatalf("the remaining old session must stay ready, ready=%d", r.sup.ReadyCount())
	}
}

func TestControllerConcurrentHandle(t *testing.T) {
	sup := NewSupervisor("bnk", "bnk.tunnel.example", "eu", false, 1, nil, nil, nil, nil, nil)
	c := &Controller{Exit: func(int) {}, Supervisors: func() []*Supervisor { return []*Supervisor{sup} }}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			reason := proto.ReasonCapExceeded
			if i%2 == 1 {
				reason = proto.ReasonAuthUnavailable
			}
			c.Handle(GoawayEvent{Pop: "bnk", Addr: netip.MustParseAddr("2001:db8::1"), Goaway: h2srv.Goaway{Reason: reason, RetryAfter: 5 * time.Second}})
		}(i)
	}
	wg.Wait()
	if !sup.Paused() || len(sup.BadAddrs()) != 1 {
		t.Fatal("both reasons must have been applied")
	}
}

func TestSupervisorRefusesSessionAfterStopping(t *testing.T) {
	opts := func(_ *Supervisor, _ int, conn *Conn) h2srv.Options {
		return h2srv.Options{Handler: http.NotFoundHandler(), Transport: conn.Transport}
	}
	sup := NewSupervisor("bnk", "bnk.tunnel.example", "eu", false, 1, nil, opts, nil, nil, nil)
	sup.ctx, sup.cancel = context.WithCancel(context.Background())
	defer sup.cancel()
	sup.stopping = true
	local, remote := net.Pipe()
	defer remote.Close()
	done := make(chan struct{})
	go func() { sup.serveSession(sup.slots[0], &Conn{Conn: local}, slog.Default()); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveSession served a session while the supervisor was stopping")
	}
	if _, err := remote.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("conn must be closed, read err %v", err)
	}
	if sup.slots[0].sess != nil {
		t.Fatal("slot must stay empty")
	}
}

func TestSupervisorDownSince(t *testing.T) {
	r := newSupRig(t, 1, false, 0)
	r.start(t)
	start := r.sup.DownSince()
	if start.IsZero() {
		t.Fatal("down since Start until the first ready session")
	}
	s1 := r.edge.WaitSession(t)
	waitCond(t, func() bool { return r.sup.ReadyCount() == 1 })
	if !r.sup.DownSince().IsZero() {
		t.Fatal("a ready session clears DownSince")
	}
	r.clock.add(time.Minute)
	r.edge.CloseListener() // the redial fails, so the pop stays down
	s1.CC.Close()
	waitCond(t, func() bool { return !r.sup.DownSince().IsZero() })
	if !r.sup.DownSince().After(start) {
		t.Fatal("DownSince restarts when the last ready session ends")
	}
}

func TestPauseAndMarkAddrBadAreClamped(t *testing.T) {
	sup := NewSupervisor("bnk", "bnk.tunnel.example", "eu", false, 1, nil, nil, nil, nil, nil)
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	sup.now = func() time.Time { return now }
	sup.Pause(48*time.Hour, "x")
	if !sup.PausedUntil().Equal(now.Add(proto.MaxPause)) {
		t.Fatalf("pause not clamped: %v", sup.PausedUntil())
	}
	sup.MarkAddrBad(netip.MustParseAddr("::1"), 48*time.Hour)
	sup.OnNoAddress()
	if !sup.PausedUntil().Equal(now.Add(proto.MaxPause)) { // never shortens the existing pause
		t.Fatalf("pause shortened: %v", sup.PausedUntil())
	}
	sup2 := NewSupervisor("bnk", "bnk.tunnel.example", "eu", false, 1, nil, nil, nil, nil, nil)
	sup2.now = sup.now
	sup2.MarkAddrBad(netip.MustParseAddr("::1"), 48*time.Hour)
	sup2.OnNoAddress()
	if !sup2.PausedUntil().Equal(now.Add(proto.MaxRetryAfterShort)) {
		t.Fatalf("auth_unavailable pause not clamped to 15m: %v", sup2.PausedUntil())
	}
}
