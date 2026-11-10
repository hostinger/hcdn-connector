package session

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hostinger/hcdn-connector/internal/h2srv"
	"github.com/hostinger/hcdn-connector/internal/proto"
	"github.com/hostinger/hcdn-connector/internal/testpki"
	"github.com/hostinger/hcdn-connector/pkg/creds"
)

type ctrlHarness struct {
	c        *Controller
	sups     []*Supervisor
	exits    []int
	reselect []bool
	afters   []func()
	afterDs  []time.Duration
	reloads  int
	changed  bool
	serial   string
	now      time.Time
}

func newHarness(t *testing.T, pops ...string) *ctrlHarness {
	t.Helper()
	h := &ctrlHarness{now: time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC), serial: "old"}
	for _, p := range pops {
		s := NewSupervisor(p, p+".tunnel.example", "eu", false, 2, nil, nil, nil, nil, nil)
		s.now = func() time.Time { return h.now }
		h.sups = append(h.sups, s)
	}
	h.c = &Controller{
		Now:  func() time.Time { return h.now },
		Exit: func(code int) { h.exits = append(h.exits, code) },
		ReloadCreds: func() (bool, error) {
			h.reloads++
			if h.changed {
				h.serial = "new"
			}
			return h.changed, nil
		},
		CurrentSerial: func() string { return h.serial },
		Reselect:      func(refresh bool) { h.reselect = append(h.reselect, refresh) },
		Supervisors:   func() []*Supervisor { return h.sups },
		After:         func(d time.Duration, f func()) { h.afterDs = append(h.afterDs, d); h.afters = append(h.afters, f) },
	}
	return h
}

func ev(pop, reason string, retry time.Duration) GoawayEvent {
	return GoawayEvent{Pop: pop, Addr: netip.MustParseAddr("2001:db8::1"), Goaway: h2srv.Goaway{Reason: reason, RetryAfter: retry}}
}

func TestControllerAuthUnavailable(t *testing.T) {
	h := newHarness(t, "bnk", "fast")
	if a := h.c.Handle(ev("bnk", proto.ReasonAuthUnavailable, 15*time.Second)); a != ActionExcludeAddr {
		t.Fatalf("action %s", a)
	}
	bnk, fast := h.sups[0], h.sups[1]
	if got := bnk.BadAddrs(); len(got) != 1 || got[0] != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("bad addrs %v", got)
	}
	if bnk.Paused() || fast.Paused() || len(fast.BadAddrs()) != 0 {
		t.Fatal("auth_unavailable must only exclude the address on that PoP")
	}
	// Every address exhausted -> the slot pauses the PoP for retry-after.
	bnk.OnNoAddress()
	if !bnk.Paused() || !bnk.PausedUntil().Equal(h.now.Add(15*time.Second)) || len(bnk.BadAddrs()) != 0 {
		t.Fatalf("pause after exhausting addresses: paused=%v until=%v", bnk.Paused(), bnk.PausedUntil())
	}
	if fast.Paused() {
		t.Fatal("other PoP must keep carrying traffic")
	}
	// The exclusion expires.
	h.c.Handle(ev("bnk", proto.ReasonAuthUnavailable, 15*time.Second))
	h.now = h.now.Add(16 * time.Second)
	if len(bnk.BadAddrs()) != 0 || bnk.Paused() {
		t.Fatal("exclusion and pause must expire")
	}
	if len(h.exits) != 0 {
		t.Fatal("must not exit")
	}
}

func TestControllerCapExceededPausesPop(t *testing.T) {
	h := newHarness(t, "bnk", "fast")
	if a := h.c.Handle(ev("bnk", proto.ReasonCapExceeded, 60*time.Second)); a != ActionPausePop {
		t.Fatalf("action %s", a)
	}
	if !h.sups[0].PausedUntil().Equal(h.now.Add(60*time.Second)) || h.sups[1].Paused() {
		t.Fatal("cap_exceeded pauses only that PoP")
	}
}

func TestControllerDisabledPausesAllAndResumes(t *testing.T) {
	h := newHarness(t, "bnk", "fast")
	if a := h.c.Handle(ev("bnk", proto.ReasonDisabled, 0)); a != ActionPauseAll {
		t.Fatalf("action %s", a)
	}
	for _, s := range h.sups {
		if !s.PausedUntil().Equal(h.now.Add(300 * time.Second)) {
			t.Fatalf("%s paused until %v, want +300s", s.Pop, s.PausedUntil())
		}
	}
	if !h.c.GlobalPauseUntil().Equal(h.now.Add(300 * time.Second)) {
		t.Fatal("global pause")
	}
	if len(h.exits) != 0 {
		t.Fatal("disabled must not exit")
	}
	if len(h.afters) != 1 || h.afterDs[0] != 300*time.Second {
		t.Fatalf("resume timer: %v", h.afterDs)
	}
	h.now = h.now.Add(301 * time.Second)
	h.afters[0]()
	if len(h.reselect) != 1 || !h.reselect[0] {
		t.Fatalf("resume must re-run selection with a pop refresh: %v", h.reselect)
	}
	for _, s := range h.sups {
		if s.Paused() {
			t.Fatalf("%s still paused after the retry-after", s.Pop)
		}
	}
	// Explicit retry-after is honored.
	h2 := newHarness(t, "bnk")
	h2.c.Handle(ev("bnk", proto.ReasonDisabled, 42*time.Second))
	if !h2.sups[0].PausedUntil().Equal(h2.now.Add(42 * time.Second)) {
		t.Fatal("explicit retry-after")
	}
}

func TestControllerOnlyRevokedExits(t *testing.T) {
	for _, reason := range []string{proto.ReasonDrain, proto.ReasonCapExceeded, proto.ReasonAuthUnavailable,
		proto.ReasonReselect, proto.ReasonDisabled, proto.ReasonProtocolError} {
		h := newHarness(t, "bnk")
		h.c.Handle(ev("bnk", reason, 5*time.Second))
		if len(h.exits) != 0 {
			t.Fatalf("%s must not exit", reason)
		}
	}
	h := newHarness(t, "bnk")
	if a := h.c.Handle(ev("bnk", proto.ReasonRevoked, 0)); a != ActionExit {
		t.Fatalf("action %s", a)
	}
	if len(h.exits) != 1 || h.exits[0] != 78 || h.c.ExitReason() != proto.ReasonRevoked {
		t.Fatalf("revoked must exit 78, got %v %q", h.exits, h.c.ExitReason())
	}
	// After the exit decision, later goaways are ignored.
	if a := h.c.Handle(ev("bnk", proto.ReasonDisabled, 0)); a != ActionAlreadyExits {
		t.Fatalf("post-exit action %s", a)
	}
}

// owner_required stops like revoked, with exit 77 (EX_NOPERM) so a script
// can tell "sign in" from "taken down".
func TestControllerOwnerRequiredExits77(t *testing.T) {
	h := newHarness(t, "bnk")
	if a := h.c.Handle(ev("bnk", proto.ReasonOwnerRequired, 0)); a != ActionExit {
		t.Fatalf("action %s", a)
	}
	if len(h.exits) != 1 || h.exits[0] != proto.ExitOwnerRequired || h.c.ExitReason() != proto.ReasonOwnerRequired {
		t.Fatalf("owner_required must exit 77, got %v %q", h.exits, h.c.ExitReason())
	}
	ee := &ExitError{Code: ExitCode(h.c.ExitReason()), Reason: h.c.ExitReason()}
	if !errors.Is(ee, ErrOwnerRequired) || errors.Is(&ExitError{Code: 78, Reason: proto.ReasonRevoked}, ErrOwnerRequired) {
		t.Fatal("only the owner_required ExitError matches ErrOwnerRequired")
	}
	if ee.Error() != "exit 77 (owner_required)" {
		t.Fatalf("message %q", ee.Error())
	}
}

func TestControllerReselect(t *testing.T) {
	h := newHarness(t, "bnk")
	if a := h.c.Handle(ev("bnk", proto.ReasonReselect, 0)); a != ActionReselect || len(h.reselect) != 1 || !h.reselect[0] {
		t.Fatalf("reselect: %s %v", a, h.reselect)
	}
}

func serialEv(serial string) GoawayEvent {
	e := ev("bnk", proto.ReasonUnknownSerial, 0)
	e.Serial = serial
	return e
}

func TestControllerUnknownSerial(t *testing.T) {
	// Credentials changed on reload: no exit.
	h := newHarness(t, "bnk")
	h.changed = true
	if a := h.c.Handle(serialEv("old")); a != ActionReloadCreds || h.reloads != 1 || len(h.exits) != 0 {
		t.Fatalf("changed creds: %s reloads=%d exits=%v", a, h.reloads, h.exits)
	}
	// The other sessions still dialed with the old serial: ignored, no reload, no exit.
	for i := 0; i < 3; i++ {
		if a := h.c.Handle(serialEv("old")); a != ActionNone || h.reloads != 1 || len(h.exits) != 0 {
			t.Fatalf("stale serial %d: %s reloads=%d exits=%v", i, a, h.reloads, h.exits)
		}
	}
	// The edge rejects the new serial too and the file has nothing newer: exit 78.
	h.changed = false
	if a := h.c.Handle(serialEv("new")); a != ActionExit || len(h.exits) != 1 || h.exits[0] != 78 {
		t.Fatalf("new serial rejected: %s %v", a, h.exits)
	}
	// Credentials unchanged on reload: exit 78.
	h2 := newHarness(t, "bnk")
	if a := h2.c.Handle(serialEv("old")); a != ActionExit || h2.reloads != 1 || len(h2.exits) != 1 || h2.exits[0] != 78 {
		t.Fatalf("unchanged creds: %s reloads=%d exits=%v", a, h2.reloads, h2.exits)
	}
	// The file watcher already loaded new credentials: the rejected serial is stale, no exit.
	h3 := newHarness(t, "bnk")
	h3.serial = "new"
	if a := h3.c.Handle(serialEv("old")); a != ActionNone || h3.reloads != 0 || len(h3.exits) != 0 {
		t.Fatalf("watcher reloaded first: %s reloads=%d exits=%v", a, h3.reloads, h3.exits)
	}
	// The watcher loads the new file between the serial check and the reload: no exit.
	h4 := newHarness(t, "bnk")
	h4.c.ReloadCreds = func() (bool, error) { h4.reloads++; h4.serial = "new"; return false, nil }
	if a := h4.c.Handle(serialEv("old")); a != ActionReloadCreds || len(h4.exits) != 0 {
		t.Fatalf("watcher raced the reload: %s exits=%v", a, h4.exits)
	}
}

func TestStormIgnoresGoaways(t *testing.T) {
	m := &Manager{Log: slog.Default()}
	for i := 0; i < 2*stormThreshold; i++ {
		m.onSessionEnd("bnk", "goaway_"+proto.ReasonDisabled)
	}
	if !m.lastStorm.IsZero() {
		t.Fatal("goaways have their own handling and must not count as a storm")
	}
	for i := 0; i < stormThreshold; i++ {
		m.onSessionEnd("bnk", "closed")
	}
	if m.lastStorm.IsZero() {
		t.Fatal("unexpected session ends must count as a storm")
	}
}

func TestControllerExitOrder(t *testing.T) {
	h := newHarness(t, "bnk")
	h.c.RevokedHint = "install new credentials"
	var order []string
	h.c.Exit = func(int) { order = append(order, "exit") }
	h.c.StopAll = func() { order = append(order, "stop") }
	h.c.Handle(ev("bnk", proto.ReasonRevoked, 0))
	if strings.Join(order, ",") != "exit,stop" {
		t.Fatalf("Exit must run before StopAll: %v", order)
	}
}

func TestUnknownSerialRefresh(t *testing.T) {
	ca := testpki.NewCA(t)
	mk := func(exp time.Duration) *creds.Credentials {
		certPEM, keyPEM := ca.IssueClient(t, tid, time.Now().Add(exp))
		c, err := creds.FromPEM(tid, certPEM, keyPEM, []string{"127.0.0.1"})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	setup := func(next *creds.Credentials, fail error) (*ctrlHarness, *creds.Store, chan struct{}, *atomic.Int32, chan int) {
		gate := make(chan struct{})
		calls := &atomic.Int32{}
		store, err := creds.NewMemoryStore(mk(time.Hour), slog.Default(), func(context.Context) (*creds.Credentials, error) {
			calls.Add(1)
			<-gate
			return next, fail
		})
		if err != nil {
			t.Fatal(err)
		}
		exits := make(chan int, 2)
		h := newHarness(t, "bnk")
		h.c.Exit = func(code int) { exits <- code }
		h.c.ReloadCreds, h.c.CanRefresh, h.c.Refresh = store.Reload, store.CanRefresh, store.Refresh
		h.c.CurrentSerial = func() string { return store.Current().Serial }
		return h, store, gate, calls, exits
	}

	h, store, gate, calls, exits := setup(mk(2*time.Hour), nil)
	rotated := make(chan struct{}, 1)
	store.OnChange(func(*creds.Credentials) { rotated <- struct{}{} })
	old := store.Current().Serial
	if a := h.c.Handle(serialEv(old)); a != ActionReloadCreds {
		t.Fatalf("Handle must return at once with reload_creds: %s", a)
	}
	waitCond(t, func() bool { return calls.Load() == 1 })
	if a := h.c.Handle(serialEv(old)); a != ActionReloadCreds {
		t.Fatalf("goaway during the refresh: %s", a)
	}
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatalf("a goaway during the refresh must not start another one: %d", calls.Load())
	}
	close(gate)
	select {
	case <-rotated:
	case <-time.After(5 * time.Second):
		t.Fatal("a refresh must trigger the session rotation")
	}
	waitCond(t, func() bool { return h.c.Handle(serialEv(old)) == ActionNone })
	if store.Current().Serial == old || len(exits) != 0 {
		t.Fatalf("refresh success: serial %s exits %d", store.Current().Serial, len(exits))
	}
	// The edge rejects the refreshed certificate too: exit 78, no second enrollment.
	if a := h.c.Handle(serialEv(store.Current().Serial)); a != ActionExit || calls.Load() != 1 {
		t.Fatalf("refreshed serial rejected: %s calls=%d", a, calls.Load())
	}
	if code := <-exits; code != proto.ExitRevoked {
		t.Fatalf("exit code %d", code)
	}

	// After the hold-off a rejection (the edge forgot the certificate) gets a new refresh.
	h, store, gate, calls, _ = setup(mk(2*time.Hour), nil)
	close(gate)
	h.c.Handle(serialEv(store.Current().Serial))
	h.c.refreshWG.Wait() // not WaitRefresh: that one stops later refreshes
	h.now = h.now.Add(refreshHoldoff)
	if a := h.c.Handle(serialEv(store.Current().Serial)); a != ActionReloadCreds {
		t.Fatalf("rejection after the hold-off: %s", a)
	}
	h.c.WaitRefresh()
	if calls.Load() != 2 {
		t.Fatalf("refreshes after the hold-off: %d", calls.Load())
	}

	// A goaway that races Manager.Run's WaitRefresh must not start a refresh after it.
	h, _, gate, calls, _ = setup(mk(2*time.Hour), nil)
	close(gate)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); h.c.Handle(serialEv(h.c.CurrentSerial())) }()
	go func() { defer wg.Done(); h.c.WaitRefresh() }()
	wg.Wait()
	h.c.WaitRefresh()
	n := calls.Load()
	if a := h.c.Handle(serialEv(h.c.CurrentSerial())); a != ActionNone || calls.Load() != n {
		t.Fatalf("goaway after WaitRefresh: %s calls %d -> %d", a, n, calls.Load())
	}

	h, _, gate, _, exits = setup(nil, errors.New("enrollment down"))
	h.c.Handle(serialEv(h.c.CurrentSerial()))
	close(gate)
	select {
	case code := <-exits:
		if code != proto.ExitRevoked {
			t.Fatalf("exit code %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a failed refresh must exit 78")
	}
}

func TestControllerExitOnce(t *testing.T) {
	h := newHarness(t, "bnk")
	stops := 0
	h.c.StopAll = func() { stops++ }
	h.c.Handle(ev("bnk", proto.ReasonRevoked, 0))
	if a := h.c.exit(proto.ReasonOwnerRequired); a != ActionAlreadyExits || h.c.ExitReason() != proto.ReasonRevoked || stops != 1 || len(h.exits) != 1 || !h.c.Exiting() {
		t.Fatalf("second exit: %s stops=%d exits=%v", a, stops, h.exits)
	}
}
