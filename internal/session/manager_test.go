package session

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hostinger/hcdn-connector/internal/h2srv"
	"github.com/hostinger/hcdn-connector/internal/ingress"
	"github.com/hostinger/hcdn-connector/internal/metrics"
	"github.com/hostinger/hcdn-connector/internal/proto"
	"github.com/hostinger/hcdn-connector/internal/testedge"
	"github.com/hostinger/hcdn-connector/internal/testpki"
	"github.com/hostinger/hcdn-connector/pkg/config"
)

type managerRig struct {
	m     *Manager
	edge  *testedge.Edge
	exits chan int
	done  chan error
	cfg   *config.Config
}

type rigOpts struct {
	mode           string
	homePops       int
	sessionsPerPop int
	manualPops     []string       // manual mode list
	pops           []testedge.Pop // discovery reply; nil = single "bnk" at 127.0.0.1
	names          []string       // extra cert DNS names
	resolver       Resolver       // nil = system resolver (IP literals only)
	ca             *testpki.CA
	edge           *testedge.Edge // reuse an edge (nil = new one; must share ca)
	svc            *httptest.Server
	drainTimeout   time.Duration
	ownerTicket    string
	ownerAbsent    string
}

func startManager(t *testing.T, mode string, homePops, sessionsPerPop int) (*managerRig, context.CancelFunc) {
	t.Helper()
	pops := []string(nil)
	if mode == config.ModeManual {
		pops = []string{"bnk"}
	}
	return startManagerOpts(t, rigOpts{mode: mode, homePops: homePops, sessionsPerPop: sessionsPerPop, manualPops: pops})
}

func startManagerOpts(t *testing.T, o rigOpts) (*managerRig, context.CancelFunc) {
	t.Helper()
	ca := o.ca
	if ca == nil {
		ca = testpki.NewCA(t)
	}
	edge := o.edge
	if edge == nil {
		edge = testedge.New(t, ca, "bnk", false, o.names...)
	}
	edge.Pops = o.pops
	svc := o.svc
	if svc == nil {
		svc = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(20 * time.Millisecond)
			w.Header().Set("X-Seen-Host", r.Host)
			io.WriteString(w, "service says hi")
		}))
		t.Cleanup(svc.Close)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, ca.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	manual := ""
	if o.mode == config.ModeManual {
		manual = "  pops: [" + strings.Join(o.manualPops, ", ") + "]\n"
	}
	cfgSrc := `
tunnel_id: ` + tid + `
credentials_file: x
server_ca_file: ` + caFile + `
home_pops: ` + strconv.Itoa(o.homePops) + `
sessions_per_pop: ` + strconv.Itoa(o.sessionsPerPop) + `
ports: [` + strconv.Itoa(edge.Port()) + `]
pop_selection:
  mode: ` + o.mode + `
` + manual + `
ingress:
  - hostname: shop.example.com
    service: ` + svc.URL + `
  - service: http_status:404
`
	cfg, err := config.Parse([]byte(cfgSrc))
	if err != nil {
		t.Fatal(err)
	}
	cs := newCreds(t, ca, "127.0.0.1")
	d := newDialer(t, ca, cs, cfg.Ports, deadPort(t))
	d.Resolver = o.resolver
	tbl, err := ingress.Build(cfg.Ingress, tid, nil)
	if err != nil {
		t.Fatal(err)
	}
	mets := metrics.New()
	exits := make(chan int, 4)
	m := &Manager{
		Config:       cfg,
		Creds:        cs,
		Dialer:       d,
		Discovery:    &Discovery{Dialer: d, Bootstrap: func() []string { return cs.Current().BootstrapEndpoints }},
		Handler:      ingress.NewHandler(tbl, tid, slog.Default(), mets),
		Metrics:      mets,
		Log:          slog.Default(),
		Version:      "0.1.0-test",
		Exit:         func(code int) { exits <- code },
		DrainTimeout: o.drainTimeout,
		OwnerTicket:  o.ownerTicket,
		OwnerAbsent:  o.ownerAbsent,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	stopped := make(chan struct{})
	go func() { done <- m.Run(ctx); close(stopped) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(20 * time.Second):
			t.Error("manager did not stop")
		}
	})
	return &managerRig{m: m, edge: edge, exits: exits, done: done, cfg: cfg}, cancel
}

func TestManagerEndToEnd(t *testing.T) {
	rig, _ := startManager(t, config.ModeAuto, 1, 1)
	s := rig.edge.WaitSession(t)
	if s.HelloErr != nil || s.Hello.StatusCode != 200 {
		t.Fatalf("hello: %v", s.HelloErr)
	}
	if s.Hello.Header.Get(proto.HdrConnVersion) != "0.1.0-test" || s.Hello.Header.Get(proto.HdrConnID) == "" ||
		s.Hello.Header.Get(proto.HdrFeatures) != "ws,owner,visible" || s.Hello.Header.Get(proto.HdrTransport) != proto.TransportDirect ||
		s.Hello.Header.Get(proto.HdrConnectedPops) != "bnk" ||
		s.Hello.Header.Get(proto.HdrOwnerAbsent) != proto.OwnerAbsentNotRequested || s.Hello.Header.Get(proto.HdrOwnerTicket) != "" {
		t.Fatalf("hello headers: %v", s.Hello.Header)
	}
	res := s.Get(t, "shop.example.com", "/index.html")
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || string(body) != "service says hi" || res.Header.Get("X-Seen-Host") != "shop.example.com" {
		t.Fatalf("proxied: %d %q %v", res.StatusCode, body, res.Header)
	}
	rt, err := strconv.Atoi(res.Header.Get(proto.HdrConnectorRT))
	if err != nil || rt < 15 || rt > 5000 {
		t.Fatalf("hcdn-connector-rt %q (service sleeps 20 ms)", res.Header.Get(proto.HdrConnectorRT))
	}
	// Request without hcdn-request-id is rejected; the catch-all answers 404.
	req, _ := http.NewRequest(http.MethodGet, "https://shop.example.com/", nil)
	if r, err := s.CC.RoundTrip(req); err != nil || r.StatusCode != 400 {
		t.Fatalf("missing request id: %v %v", err, r)
	}
	if r := s.Get(t, "nope.example.net", "/"); r.StatusCode != 404 {
		t.Fatalf("catch-all %d", r.StatusCode)
	}

	waitCond(t, func() bool { return len(rig.m.Status().Pops) == 1 && rig.m.Status().Pops[0].Ready == 1 })
	st := rig.m.Status()
	if st.Selection.Pops[0] != "bnk" || len(st.Selection.Probes) != 1 || !st.Selection.Probes[0].Selected || st.Selection.Probes[0].RTTms <= 0 {
		t.Fatalf("status selection: %+v", st.Selection)
	}
	if st.Pops[0].Sessions[0].State != StateReady || st.Pops[0].Sessions[0].EdgeNode != "bnk-edge1" || st.Pops[0].Sessions[0].Transport != proto.TransportDirect {
		t.Fatalf("status session: %+v", st.Pops[0].Sessions[0])
	}
	if got := rig.m.ConnectedPops(); len(got) != 1 || got[0] != "bnk" {
		t.Fatalf("connected pops %v", got)
	}

	// disabled: session closes, PoP pauses for retry-after, then reconnects (no exit).
	s.Goaway(t, proto.ReasonDisabled, 1)
	waitCond(t, func() bool {
		st := rig.m.Status()
		return len(st.Pops) == 1 && st.Pops[0].Ready == 0 && st.Pops[0].PauseReason == proto.ReasonDisabled
	})
	s2 := rig.edge.WaitSession(t)
	if s2.HelloErr != nil {
		t.Fatalf("reconnect after disabled: %v", s2.HelloErr)
	}
	select {
	case code := <-rig.exits:
		t.Fatalf("disabled must not exit (got %d)", code)
	default:
	}
	// drain: the connector reconnects right away.
	s2.Goaway(t, proto.ReasonDrain, 0)
	s2.CC.Close()
	s3 := rig.edge.WaitSession(t)
	if s3.HelloErr != nil {
		t.Fatalf("reconnect after drain: %v", s3.HelloErr)
	}
}

func TestManagerRevokedExits78(t *testing.T) {
	rig, _ := startManager(t, config.ModeManual, 1, 1)
	s := rig.edge.WaitSession(t)
	if s.HelloErr != nil {
		t.Fatal(s.HelloErr)
	}
	s.Goaway(t, proto.ReasonRevoked, 0)
	select {
	case code := <-rig.exits:
		if code != proto.ExitRevoked {
			t.Fatalf("exit code %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("revoked did not exit")
	}
	select {
	case err := <-rig.done:
		var ee *ExitError
		if !errors.As(err, &ee) || ee.Code != proto.ExitRevoked || ee.Reason != proto.ReasonRevoked || errors.Is(err, ErrOwnerRequired) {
			t.Fatalf("Run must return exit 78, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after stopAll")
	}
	if len(rig.m.Supervisors()) != 0 {
		t.Fatal("supervisors must be stopped")
	}
}

func TestMergeTrigger(t *testing.T) {
	for _, c := range []struct{ pending, next, want string }{
		{"", "reprobe", "reprobe"},
		{"reprobe", "goaway_refresh", "goaway_refresh"},
		{"goaway_refresh", "reprobe", "goaway_refresh"},
		{"storm", "pops_gen", "storm"},
	} {
		if got := mergeTrigger(c.pending, c.next); got != c.want {
			t.Fatalf("mergeTrigger(%q, %q) = %q, want %q", c.pending, c.next, got, c.want)
		}
	}
}

func TestManagerCheckPopsDown(t *testing.T) {
	m := &Manager{Log: slog.Default(), sups: map[string]*Supervisor{}, reselectCh: make(chan string, 4)}
	s := NewSupervisor("bnk", "bnk.tunnel.example", "eu", false, 1, nil, nil, nil, nil, nil)
	now := time.Now()
	clock := now
	s.now = func() time.Time { return clock }
	s.downSince = now
	m.sups["bnk"] = s
	triggers := func() int { return len(m.reselectCh) }

	m.checkPopsDown(now.Add(popDownAfter - time.Second))
	if triggers() != 0 {
		t.Fatal("fired before popDownAfter")
	}
	m.checkPopsDown(now.Add(popDownAfter))
	if triggers() != 1 || <-m.reselectCh != "pop_down" {
		t.Fatal("no pop_down trigger")
	}
	m.checkPopsDown(now.Add(popDownAfter + 10*time.Second))
	if triggers() != 0 {
		t.Fatal("pop_down must be rate limited")
	}
	clock = now.Add(2 * time.Minute)
	s.Pause(time.Hour, proto.ReasonDisabled)
	m.checkPopsDown(now.Add(10 * time.Minute))
	if triggers() != 0 {
		t.Fatal("a paused pop is not down")
	}
	// The pause time does not count: the clock restarts when the pause ends.
	pauseEnd := s.PausedUntil()
	m.checkPopsDown(pauseEnd.Add(popDownAfter - time.Second))
	if triggers() != 0 {
		t.Fatal("fired right after the pause ended")
	}
	m.checkPopsDown(pauseEnd.Add(popDownAfter))
	if triggers() != 1 {
		t.Fatal("no pop_down trigger popDownAfter past the pause")
	}
}

func TestManagerManualModeWithoutDiscovery(t *testing.T) {
	rig, _ := startManager(t, config.ModeManual, 1, 2)
	s := rig.edge.WaitSession(t)
	if s.HelloErr != nil {
		t.Fatal(s.HelloErr)
	}
	s2 := rig.edge.WaitSession(t)
	if s2.HelloErr != nil {
		t.Fatal(s2.HelloErr)
	}
	waitCond(t, func() bool { st := rig.m.Status(); return len(st.Pops) == 1 && st.Pops[0].Ready == 2 })
	if st := rig.m.Status(); st.Selection.Reason == "" || st.Selection.Pops[0] != "bnk" {
		t.Fatalf("selection %+v", st.Selection)
	}
}

// twoPopRig: one fake edge serves both "bnk.test" and "fast.test" (static resolver).
func twoPopRig(t *testing.T, manual []string, homePops int) (*managerRig, *testedge.Edge) {
	t.Helper()
	ca := testpki.NewCA(t)
	edge := testedge.New(t, ca, "bnk", false, "bnk.test", "fast.test")
	pops := []testedge.Pop{
		{Code: "bnk", Endpoint: "bnk.test", Region: "eu-north", Allowed: true},
		{Code: "fast", Endpoint: "fast.test", Region: "eu-west", Allowed: true},
	}
	rig, _ := startManagerOpts(t, rigOpts{mode: config.ModeManual, homePops: homePops, sessionsPerPop: 1,
		manualPops: manual, pops: pops, ca: ca, edge: edge, resolver: testedge.StaticResolver{"bnk.test": {"127.0.0.1"}, "fast.test": {"127.0.0.1"}}})
	return rig, edge
}

func TestManagerApplyNewFirstThenDrain(t *testing.T) {
	rig, edge := twoPopRig(t, []string{"bnk"}, 1)
	s1 := edge.WaitSession(t)
	if s1.HelloErr != nil {
		t.Fatal(s1.HelloErr)
	}
	waitCond(t, func() bool { st := rig.m.Status(); return len(st.Pops) == 1 && st.Pops[0].Ready == 1 })

	// Hold the hello of the next session so "new first, then drain" is observable.
	gate := make(chan struct{})
	edge.SetHelloGate(gate)
	rig.cfg.PopSelection.Pops = []string{"fast"}
	rig.m.requestReselect("test")
	waitCond(t, func() bool { return edge.Dials.Load() == 2 })
	time.Sleep(100 * time.Millisecond)
	if s1.CC.State().Closing || s1.CC.State().Closed {
		t.Fatal("old PoP drained before the new one was ready")
	}
	if sups := rig.m.Supervisors(); len(sups) != 2 {
		t.Fatalf("both supervisors must exist during the switch: %d", len(sups))
	}
	gate <- struct{}{}
	s2 := edge.WaitSession(t)
	if s2.HelloErr != nil || s2.Hello.Header.Get(proto.HdrConnectedPops) != "bnk,fast" {
		t.Fatalf("new session hello: %v %v", s2.HelloErr, s2.Hello)
	}
	waitCond(t, func() bool { return s1.CC.State().Closing || s1.CC.State().Closed })
	waitCond(t, func() bool { sups := rig.m.Supervisors(); return len(sups) == 1 && sups[0].Pop == "fast" })
}

func TestDrainableKeepsReadyPopCount(t *testing.T) {
	sup := func(code string, ready int) *Supervisor {
		s := NewSupervisor(code, code+".test", "", false, 2, nil, nil, nil, nil, nil)
		for i := 0; i < ready; i++ {
			s.slots[i].state = StateReady
		}
		return s
	}
	a, b, down := sup("a", 2), sup("b", 1), sup("down", 0)
	removed := []*Supervisor{a, b, down}
	codes := func(s []*Supervisor) string { return strings.Join(popCodes(s), ",") }

	if got := codes(drainable(removed, 1)); got != "down,b" {
		t.Fatalf("one new pop ready: drain the dead pop and the weakest ready one, got %s", got)
	}
	if got := codes(drainable(removed, 2)); got != "down,b,a" {
		t.Fatalf("two new pops ready: drain all, got %s", got)
	}
	if got := codes(drainable(removed, 5)); got != "down,b,a" {
		t.Fatalf("more ready than removed: %s", got)
	}
}

func TestManagerNewSupervisorInheritsDisabledPause(t *testing.T) {
	rig, edge := twoPopRig(t, []string{"bnk"}, 2)
	s1 := edge.WaitSession(t)
	if s1.HelloErr != nil {
		t.Fatal(s1.HelloErr)
	}
	s1.Goaway(t, proto.ReasonDisabled, 30)
	waitCond(t, func() bool { return !rig.m.Status().GlobalPauseUntil.IsZero() })
	dials := edge.Dials.Load()

	rig.cfg.PopSelection.Pops = []string{"bnk", "fast"}
	rig.m.requestReselect("test")
	waitCond(t, func() bool { return len(rig.m.Supervisors()) == 2 })
	var fast *Supervisor
	for _, s := range rig.m.Supervisors() {
		if s.Pop == "fast" {
			fast = s
		}
	}
	if !fast.Paused() || fast.Snapshot().PauseReason != proto.ReasonDisabled {
		t.Fatalf("new supervisor must inherit the global pause: %+v", fast.Snapshot())
	}
	if until := fast.PausedUntil(); until.Sub(rig.m.Status().GlobalPauseUntil).Abs() > 2*time.Second {
		t.Fatalf("pause end %v vs global %v", until, rig.m.Status().GlobalPauseUntil)
	}
	time.Sleep(200 * time.Millisecond)
	if edge.Dials.Load() != dials {
		t.Fatal("a paused supervisor must not dial")
	}
}

func TestManagerPopsGenChangeRefreshesDiscovery(t *testing.T) {
	old := refreshMinGap
	refreshMinGap = 0
	t.Cleanup(func() { refreshMinGap = old })
	rig, _ := startManager(t, config.ModeAuto, 1, 1)
	s1 := rig.edge.WaitSession(t)
	if s1.HelloErr != nil {
		t.Fatal(s1.HelloErr)
	}
	waitCond(t, func() bool { return rig.m.Status().Selection.PopsGen == 41 })
	fetched := rig.m.Discovery.Cached().FetchedAt

	rig.edge.PopsGen.Store(42)
	s1.CC.Close() // reconnect: the next hello carries the new generation
	s2 := rig.edge.WaitSession(t)
	if s2.HelloErr != nil {
		t.Fatal(s2.HelloErr)
	}
	waitCond(t, func() bool {
		st := rig.m.Status()
		return st.Selection.PopsGen == 42 && st.Selection.Trigger == "pops_gen"
	})
	if !rig.m.Discovery.Cached().FetchedAt.After(fetched) {
		t.Fatal("pop list must be refetched on a generation change")
	}
}

// Every session's hello carries the run's ticket, or its no-ticket reason;
// goaway owner_required stops the run with exit 77.
func TestManagerOwnerHelloAndOwnerRequired(t *testing.T) {
	rig, _ := startManagerOpts(t, rigOpts{mode: config.ModeManual, homePops: 1, sessionsPerPop: 2, manualPops: []string{"bnk"},
		ownerTicket: "aaa.bbb.ccc", ownerAbsent: proto.OwnerAbsentNoToken})
	for i := 0; i < 2; i++ {
		s := rig.edge.WaitSession(t)
		if s.HelloErr != nil || s.Hello.Header.Get(proto.HdrOwnerTicket) != "aaa.bbb.ccc" || s.Hello.Header.Get(proto.HdrOwnerAbsent) != "" {
			t.Fatalf("hello %d: %v %v", i, s.HelloErr, s.Hello.Header)
		}
		if i == 1 {
			s.Goaway(t, proto.ReasonOwnerRequired, 0)
		}
	}
	select {
	case code := <-rig.exits:
		if code != proto.ExitOwnerRequired {
			t.Fatalf("exit code %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("owner_required did not exit")
	}
	select {
	case err := <-rig.done:
		var ee *ExitError
		if !errors.As(err, &ee) || ee.Code != proto.ExitOwnerRequired || ee.Reason != proto.ReasonOwnerRequired || !errors.Is(err, ErrOwnerRequired) {
			t.Fatalf("Run must return exit 77, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after stopAll")
	}
}

func TestManagerExitDefault(t *testing.T) {
	m := &Manager{Creds: newCreds(t, testpki.NewCA(t), "127.0.0.1"), Log: slog.Default()}
	m.Init()
	m.Exit(proto.ExitRevoked) // os.Exit here would end the test binary
	if a := m.ctrl.Handle(GoawayEvent{Pop: "bnk", Goaway: h2srv.Goaway{Reason: proto.ReasonRevoked}}); a != ActionExit {
		t.Fatalf("action %s", a)
	}
}

func TestManagerDrainTimeout(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(svc.Close)
	t.Cleanup(func() { close(release) })
	const budget = 700 * time.Millisecond
	rig, cancel := startManagerOpts(t, rigOpts{mode: config.ModeManual, homePops: 1, sessionsPerPop: 1, manualPops: []string{"bnk"},
		svc: svc, drainTimeout: budget})
	s := rig.edge.WaitSession(t)
	if s.HelloErr != nil {
		t.Fatal(s.HelloErr)
	}
	waitCond(t, func() bool { st := rig.m.Status(); return len(st.Pops) == 1 && st.Pops[0].Ready == 1 })
	go func() {
		req, _ := http.NewRequest(http.MethodGet, "https://shop.example.com/slow", nil)
		req.Header.Set(proto.HdrRequestID, "rid-slow")
		if res, err := s.CC.RoundTrip(req); err == nil {
			res.Body.Close()
		}
	}()
	<-entered
	start := time.Now()
	cancel()
	select {
	case <-rig.done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
	if el := time.Since(start); el < budget-100*time.Millisecond || el > budget+3*time.Second {
		t.Fatalf("an in-flight request must hold Run for about DrainTimeout (%v), took %v", budget, el)
	}

	idle, cancelIdle := startManagerOpts(t, rigOpts{mode: config.ModeManual, homePops: 1, sessionsPerPop: 1, manualPops: []string{"bnk"},
		drainTimeout: 10 * time.Second})
	if s := idle.edge.WaitSession(t); s.HelloErr != nil {
		t.Fatal(s.HelloErr)
	}
	waitCond(t, func() bool { st := idle.m.Status(); return len(st.Pops) == 1 && st.Pops[0].Ready == 1 })
	start = time.Now()
	cancelIdle()
	select {
	case <-idle.done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("an idle session must not wait for the drain budget: %v", el)
	}

	// The per-session h2srv limit must not cut a budget above its 15 s default.
	sup, conn := &Supervisor{Pop: "bnk"}, &Conn{}
	for d, want := range map[time.Duration]time.Duration{0: drainBudget, time.Second: drainBudget, time.Minute: time.Minute} {
		m := &Manager{Log: slog.Default(), DrainTimeout: d}
		if got := m.sessionOptions(sup, 0, conn).DrainTimeout; got != want {
			t.Fatalf("DrainTimeout %v: session limit %v, want %v", d, got, want)
		}
	}
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
