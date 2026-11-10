package session

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hostinger/hcdn-connector/pkg/config"
)

func msd(n int) time.Duration { return time.Duration(n) * time.Millisecond }

func autoPolicy() Policy {
	return Policy{HomePops: 2, MinGainPct: 20, MinGainMs: 15, Holddown: 30 * time.Minute, Mode: config.ModeAuto}
}

func TestSelectFastestWithRegionDiversity(t *testing.T) {
	cands := []Candidate{
		{Code: "fra", Region: "eu-central", Allowed: true, RTT: msd(10)},
		{Code: "dus", Region: "eu-central", Allowed: true, RTT: msd(12)},
		{Code: "phx", Region: "us-west", Allowed: true, RTT: msd(90)},
		{Code: "mum", Region: "ap-south", Allowed: false, RTT: msd(5)},
		{Code: "bos", Region: "us-east", Allowed: true, Err: "timeout"},
	}
	sel, reason := Select(cands, nil, autoPolicy(), time.Now())
	if !reflect.DeepEqual(sel, []string{"fra", "phx"}) {
		t.Fatalf("got %v (%s)", sel, reason)
	}
	// Single-region list: the second PoP is still distinct.
	sel, _ = Select(cands[:2], nil, autoPolicy(), time.Now())
	if !reflect.DeepEqual(sel, []string{"fra", "dus"}) {
		t.Fatalf("same-region fallback: %v", sel)
	}
}

func TestSelectPinnedFirst(t *testing.T) {
	cands := []Candidate{
		{Code: "fra", Region: "eu-central", Allowed: true, RTT: msd(10)},
		{Code: "phx", Region: "us-west", Allowed: true, RTT: msd(90)},
		{Code: "mum", Region: "ap-south", Allowed: true, Pinned: true, Err: "unreachable"},
	}
	sel, reason := Select(cands, nil, autoPolicy(), time.Now())
	if !reflect.DeepEqual(sel, []string{"mum", "fra"}) || !strings.Contains(reason, "mum: pinned") {
		t.Fatalf("got %v (%s)", sel, reason)
	}
}

func TestSelectSwitchThresholdsAndHolddown(t *testing.T) {
	now := time.Now()
	pol := autoPolicy()
	pol.HomePops = 1
	cands := []Candidate{
		{Code: "fra", Region: "eu", Allowed: true, RTT: msd(100)},
		{Code: "dus", Region: "eu", Allowed: true, RTT: msd(70)},
	}
	// Inside holddown: keep fra.
	cur := []Current{{Code: "fra", Since: now.Add(-10 * time.Minute), Ready: true}}
	if sel, _ := Select(cands, cur, pol, now); !reflect.DeepEqual(sel, []string{"fra"}) {
		t.Fatalf("holddown ignored: %v", sel)
	}
	// Past holddown and 30 ms / 30 % faster: switch.
	cur[0].Since = now.Add(-time.Hour)
	if sel, reason := Select(cands, cur, pol, now); !reflect.DeepEqual(sel, []string{"dus"}) || !strings.Contains(reason, "switch fra -> dus") {
		t.Fatalf("no switch: %v (%s)", sel, reason)
	}
	// 10 ms faster (10 %): below both thresholds, no switch.
	cands[1].RTT = msd(90)
	if sel, _ := Select(cands, cur, pol, now); !reflect.DeepEqual(sel, []string{"fra"}) {
		t.Fatalf("switched below threshold: %v", sel)
	}
	// 25 % but only 12 ms faster: ms threshold fails.
	cands[0].RTT, cands[1].RTT = msd(48), msd(36)
	if sel, _ := Select(cands, cur, pol, now); !reflect.DeepEqual(sel, []string{"fra"}) {
		t.Fatalf("switched below ms threshold: %v", sel)
	}
	// Current PoP no longer allowed: replaced regardless of holddown.
	cands[0].Allowed = false
	cur[0].Since = now
	if sel, _ := Select(cands, cur, pol, now); !reflect.DeepEqual(sel, []string{"dus"}) {
		t.Fatalf("disallowed pop kept: %v", sel)
	}
	// Current PoP unreachable but still carrying sessions: kept.
	cands[0].Allowed, cands[0].Err = true, "probe timeout"
	if sel, _ := Select(cands, cur, pol, now); !reflect.DeepEqual(sel, []string{"fra"}) {
		t.Fatalf("pop with live sessions dropped: %v", sel)
	}
	// Unreachable and no sessions: dropped.
	cur[0].Ready = false
	if sel, _ := Select(cands, cur, pol, now); !reflect.DeepEqual(sel, []string{"dus"}) {
		t.Fatalf("dead pop kept: %v", sel)
	}
}

func TestSelectReplacesDownPop(t *testing.T) {
	now := time.Now()
	cands := []Candidate{
		{Code: "fra", Region: "eu", Allowed: true, RTT: msd(10)},
		{Code: "phx", Region: "us", Allowed: true, RTT: msd(90)},
		{Code: "lax", Region: "us", Allowed: true, RTT: msd(95)},
	}
	// phx still answers probes but has no ready session: replaced inside holddown.
	cur := []Current{{Code: "fra", Since: now, Ready: true}, {Code: "phx", Since: now, Down: true}}
	sel, reason := Select(cands, cur, autoPolicy(), now)
	if !reflect.DeepEqual(sel, []string{"fra", "lax"}) || !strings.Contains(reason, "phx: dropped (no ready session)") {
		t.Fatalf("down pop kept: %v (%s)", sel, reason)
	}
	// No alternative: keep the down pop rather than leave the slot empty.
	sel, reason = Select(cands[:2], cur, autoPolicy(), now)
	if !reflect.DeepEqual(sel, []string{"fra", "phx"}) || !strings.Contains(reason, "no alternative") {
		t.Fatalf("down pop without alternative: %v (%s)", sel, reason)
	}
}

func TestSelectZeroThresholdsIgnoreTies(t *testing.T) {
	now := time.Now()
	pol := Policy{HomePops: 1, Mode: config.ModeAuto}
	cands := []Candidate{
		{Code: "fra", Region: "eu", Allowed: true, RTT: msd(20)},
		{Code: "dus", Region: "eu", Allowed: true, RTT: msd(20)},
	}
	cur := []Current{{Code: "fra", Since: now, Ready: true}}
	if sel, reason := Select(cands, cur, pol, now); !reflect.DeepEqual(sel, []string{"fra"}) {
		t.Fatalf("tie switched: %v (%s)", sel, reason)
	}
	cands[1].RTT = msd(19)
	if sel, reason := Select(cands, cur, pol, now); !reflect.DeepEqual(sel, []string{"dus"}) {
		t.Fatalf("zero thresholds must switch on any gain: %v (%s)", sel, reason)
	}
}

func TestSelectSwitchKeepsRegionDiversity(t *testing.T) {
	now := time.Now()
	cands := []Candidate{
		{Code: "fra", Region: "eu", Allowed: true, RTT: msd(10)},
		{Code: "phx", Region: "us", Allowed: true, RTT: msd(90)},
		{Code: "ams", Region: "eu", Allowed: true, RTT: msd(12)},
	}
	cur := []Current{{Code: "fra", Since: now.Add(-time.Hour), Ready: true}, {Code: "phx", Since: now.Add(-time.Hour), Ready: true}}
	if sel, reason := Select(cands, cur, autoPolicy(), now); !reflect.DeepEqual(sel, []string{"fra", "phx"}) {
		t.Fatalf("switch dropped the only us pop: %v (%s)", sel, reason)
	}
	cands = append(cands, Candidate{Code: "lax", Region: "us", Allowed: true, RTT: msd(40)})
	if sel, reason := Select(cands, cur, autoPolicy(), now); !reflect.DeepEqual(sel, []string{"fra", "lax"}) {
		t.Fatalf("same-region replacement: %v (%s)", sel, reason)
	}
}

func TestSelectManual(t *testing.T) {
	pol := Policy{HomePops: 2, Mode: config.ModeManual, ManualPops: []string{"bnk", "mum", "nope"}}
	cands := []Candidate{
		{Code: "bnk", Allowed: true},
		{Code: "mum", Allowed: false},
		{Code: "fra", Allowed: true, RTT: msd(1)},
	}
	sel, reason := Select(cands, nil, pol, time.Now())
	if !reflect.DeepEqual(sel, []string{"bnk"}) || !strings.Contains(reason, "mum (not allowed)") || !strings.Contains(reason, "nope (not in pop list)") {
		t.Fatalf("manual: %v (%s)", sel, reason)
	}
	pol.ManualPops = []string{"bnk", "fra"}
	pol.HomePops = 1
	if sel, _ := Select(cands, nil, pol, time.Now()); !reflect.DeepEqual(sel, []string{"bnk"}) {
		t.Fatalf("manual truncated to home_pops: %v", sel)
	}
}

func TestManualPopsEndpoints(t *testing.T) {
	r := ManualPops([]string{"bnk", "fast"}, []string{"fra.tunnel.hostinger.dev", "fast.tunnel.hostinger.dev"})
	if r.Pops[0].Endpoint != "bnk.tunnel.hostinger.dev" || r.Pops[1].Endpoint != "fast.tunnel.hostinger.dev" {
		t.Fatalf("%+v", r.Pops)
	}
	// Spike setup: an IP literal bootstrap is used as-is for every manual PoP.
	r = ManualPops([]string{"bnk"}, []string{"127.0.0.1"})
	if r.Pops[0].Endpoint != "127.0.0.1" {
		t.Fatalf("%+v", r.Pops)
	}
}
