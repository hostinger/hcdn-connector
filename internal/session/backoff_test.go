package session

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestBackoffBounds(t *testing.T) {
	b := NewBackoff()
	b.rnd = func() float64 { return 1 } // upper bound of the jitter range
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60, 60}
	for i, w := range want {
		got := b.Next()
		if got != w*time.Second {
			t.Fatalf("attempt %d: got %v want %v", i, got, w*time.Second)
		}
	}
	b.Reset()
	if got := b.Next(); got != time.Second {
		t.Fatalf("after reset: %v", got)
	}
}

func TestBackoffFullJitter(t *testing.T) {
	b := NewBackoff()
	for i := 0; i < 200; i++ {
		d := b.Next()
		if d < 0 || d > BackoffMax {
			t.Fatalf("attempt %d: %v out of [0, 60s]", i, d)
		}
	}
	b.rnd = func() float64 { return 0 }
	if d := b.Next(); d != 0 {
		t.Fatalf("full jitter lower bound must be 0, got %v", d)
	}
}

func TestPortMemory(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	pm := NewPortMemory([]int{7844, 443})
	pm.now = func() time.Time { return now }
	ep := "bnk.tunnel.example"
	if o := pm.Order(ep); o[0] != 7844 {
		t.Fatalf("default order %v", o)
	}
	pm.RecordPrimaryFailure(ep, nil, nil)
	pm.RecordSuccess(ep, 443)
	if o := pm.Order(ep); o[0] != 443 || o[1] != 7844 {
		t.Fatalf("after 443 success: %v", o)
	}
	if pm.Working(ep) != 443 {
		t.Fatal("working port")
	}
	now = now.Add(PrimaryRetestMin - time.Second)
	if o := pm.Order(ep); o[0] != 443 {
		t.Fatalf("within the first re-test interval: %v", o)
	}
	now = now.Add(time.Second) // 1 min after the primary failure: re-test 7844 first
	if o := pm.Order(ep); o[0] != 7844 {
		t.Fatalf("first re-test after %v: %v", PrimaryRetestMin, o)
	}
	// The re-test fails and 443 works: 443 first again, for twice the interval.
	pm.RecordPrimaryFailure(ep, nil, nil)
	pm.RecordSuccess(ep, 443)
	if o := pm.Order(ep); o[0] != 443 {
		t.Fatalf("after a failed re-test: %v", o)
	}
	now = now.Add(2*PrimaryRetestMin - time.Second)
	if o := pm.Order(ep); o[0] != 443 {
		t.Fatalf("doubled interval not over: %v", o)
	}
	now = now.Add(time.Second)
	if o := pm.Order(ep); o[0] != 7844 {
		t.Fatalf("second re-test: %v", o)
	}
	// A failure inside the interval (not a re-test) does not grow it.
	pm.RecordPrimaryFailure(ep, nil, nil)
	now = now.Add(time.Second)
	pm.RecordPrimaryFailure(ep, nil, nil)
	if got := pm.entries[ep].retest; got != 4*PrimaryRetestMin {
		t.Fatalf("interval after a failed re-test and one in-window failure: %v", got)
	}
	// Repeated failed re-tests cap at PrimaryRetestTime.
	for i := 0; i < 20; i++ {
		now = now.Add(pm.entries[ep].retest)
		pm.RecordPrimaryFailure(ep, nil, nil)
		pm.RecordSuccess(ep, 443)
	}
	if got := pm.entries[ep].retest; got != PrimaryRetestTime {
		t.Fatalf("interval cap: %v", got)
	}
	now = now.Add(23 * time.Hour)
	if o := pm.Order(ep); o[0] != 443 {
		t.Fatalf("capped: within 24h: %v", o)
	}
	now = now.Add(2 * time.Hour)
	if o := pm.Order(ep); o[0] != 7844 {
		t.Fatalf("capped: daily re-test: %v", o)
	}
	pm.RecordSuccess(ep, 7844)
	if o := pm.Order(ep); o[0] != 7844 {
		t.Fatalf("primary works again: %v", o)
	}
	// A primary success resets the interval: the next fallback re-tests after 1 min again.
	pm.RecordPrimaryFailure(ep, nil, nil)
	pm.RecordSuccess(ep, 443)
	now = now.Add(PrimaryRetestMin)
	if o := pm.Order(ep); o[0] != 7844 {
		t.Fatalf("interval reset by a primary success: %v", o)
	}
}

func TestPortMemoryNeedsEveryAddressDown(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	pm := NewPortMemory([]int{7844, 443})
	pm.now = func() time.Time { return now }
	ep := "bnk.tunnel.example"
	a, b := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	resolved := []netip.Addr{a, b}

	pm.RecordPrimaryFailure(ep, []netip.Addr{a}, resolved)
	pm.RecordSuccess(ep, 443)
	if o := pm.Order(ep); o[0] != 7844 {
		t.Fatalf("one node down must not move the endpoint to 443: %v", o)
	}
	pm.RecordPrimaryFailure(ep, []netip.Addr{b}, resolved)
	if o := pm.Order(ep); o[0] != 443 {
		t.Fatalf("7844 down on every address: %v", o)
	}
	// Inside the window, a later failure on one address (after 443 failed too) keeps 443 first.
	now = now.Add(PrimaryRetestMin / 2)
	pm.RecordPrimaryFailure(ep, []netip.Addr{a}, resolved)
	if o := pm.Order(ep); o[0] != 443 {
		t.Fatalf("a partial failure must not undo primaryDown inside the window: %v", o)
	}
	// A re-test that fails on one address, then on the other, still doubles the interval.
	now = now.Add(PrimaryRetestMin)
	pm.RecordPrimaryFailure(ep, []netip.Addr{a}, resolved)
	pm.RecordPrimaryFailure(ep, []netip.Addr{b}, resolved)
	if got := pm.entries[ep].retest; got != 2*PrimaryRetestMin {
		t.Fatalf("interval after a re-test that failed address by address: %v", got)
	}
	if o := pm.Order(ep); o[0] != 443 {
		t.Fatalf("7844 down on every address after the re-test: %v", o)
	}

	// Re-test day: a failure on one address alone does not keep 443 first.
	now = now.Add(PrimaryRetestTime + time.Hour)
	pm.RecordPrimaryFailure(ep, []netip.Addr{a}, resolved)
	pm.RecordSuccess(ep, 443)
	if o := pm.Order(ep); o[0] != 7844 {
		t.Fatalf("re-test failed on one address only: %v", o)
	}
	pm.RecordSuccess(ep, 7844)
	if o := pm.Order(ep); o[0] != 7844 || pm.entries[ep].failed != nil {
		t.Fatalf("a primary success clears the failure set: %v", o)
	}

	// A failure older than the re-test time does not count toward "every address".
	pm.RecordPrimaryFailure(ep, []netip.Addr{a}, resolved)
	now = now.Add(PrimaryRetestTime)
	pm.RecordPrimaryFailure(ep, []netip.Addr{b}, resolved)
	pm.RecordSuccess(ep, 443)
	if o := pm.Order(ep); o[0] != 7844 {
		t.Fatalf("a stale failure must not count: %v", o)
	}
}

func TestProbeFailureNeedsEveryAddressDown(t *testing.T) {
	pm := NewPortMemory([]int{7844, 443})
	ep := "bnk.tunnel.example"
	a, b := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	// TLS completed, then the ping stalled: a node problem, not a blocked port.
	recordPrimaryFailure(pm, ep, errors.New("ping: i/o timeout"))
	// One sample timed out on one of two nodes.
	recordPrimaryFailure(pm, ep, &AddrError{Err: errors.New("i/o timeout"), Failed: []netip.Addr{a}, Resolved: []netip.Addr{a, b}})
	pm.RecordSuccess(ep, 443)
	if o := pm.Order(ep); o[0] != 7844 {
		t.Fatalf("one failed probe must not move the endpoint to 443: %v", o)
	}
	recordPrimaryFailure(pm, ep, &AddrError{Err: errors.New("refused"), Failed: []netip.Addr{b}, Resolved: []netip.Addr{a, b}})
	if o := pm.Order(ep); o[0] != 443 {
		t.Fatalf("7844 down on every address: %v", o)
	}
}
