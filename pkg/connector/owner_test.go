package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hostinger/hcdn-connector/internal/testedge"
	"github.com/hostinger/hcdn-connector/internal/testpki"
	"github.com/hostinger/hcdn-connector/pkg/config"
	"github.com/hostinger/hcdn-connector/pkg/creds"
)

// ownerVectors are the edge's owner ticket test vectors, copied as is.
type ownerVectors struct {
	Config struct {
		Issuer string `json:"issuer"`
	} `json:"config"`
	Valid []struct {
		Name, Ticket, Sub, Iss string
	} `json:"valid"`
	Invalid []struct {
		Name, Ticket, Expect string
	} `json:"invalid"`
}

func loadOwnerVectors(t *testing.T) *ownerVectors {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "owner_ticket.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v ownerVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func (v *ownerVectors) valid(t *testing.T, name string) string {
	t.Helper()
	for _, c := range v.Valid {
		if c.Name == name {
			return c.Ticket
		}
	}
	t.Fatalf("no valid vector %q", name)
	return ""
}

func (v *ownerVectors) invalid(t *testing.T, name string) string {
	t.Helper()
	for _, c := range v.Invalid {
		if c.Name == name {
			return c.Ticket
		}
	}
	t.Fatalf("no invalid vector %q", name)
	return ""
}

type ownerRig struct {
	edge  *testedge.Edge
	opts  WhoamiOptions
	creds *creds.Credentials
}

func newOwnerRig(t *testing.T, mode, issuer string) *ownerRig {
	t.Helper()
	ca := testpki.NewCA(t)
	edge := testedge.New(t, ca, "bnk", false)
	edge.SetQuickZone("hostingerpreview.dev")
	edge.OwnerMode, edge.OwnerIssuer = mode, issuer
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
	return &ownerRig{edge: edge, creds: c, opts: WhoamiOptions{Credentials: s, Ports: []int{edge.Port()}, ServerCAFile: caFile}}
}

// link runs the first whoami and LinkOwner, like a quick run.
func (r *ownerRig) link(t *testing.T, fn OwnerTicketFunc) (OwnerLink, error) {
	t.Helper()
	w, err := Whoami(context.Background(), r.opts)
	if err != nil {
		t.Fatal(err)
	}
	return LinkOwner(context.Background(), r.opts, w, fn)
}

// fakeIssuer answers OwnerTicketFunc calls from a script and records them.
type fakeIssuer struct {
	mu      sync.Mutex
	answers []func(ctx context.Context) (string, error)
	calls   int
	tids    []string
	expiry  []time.Time
	budgets []time.Duration
}

func (f *fakeIssuer) fn(ctx context.Context, tunnelID string, notAfter time.Time) (string, error) {
	f.mu.Lock()
	i := f.calls
	f.calls++
	f.tids = append(f.tids, tunnelID)
	f.expiry = append(f.expiry, notAfter)
	if dl, ok := ctx.Deadline(); ok {
		f.budgets = append(f.budgets, time.Until(dl))
	}
	a := f.answers[min(i, len(f.answers)-1)]
	f.mu.Unlock()
	return a(ctx)
}

func ret(ticket string, err error) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return ticket, err }
}

func TestLinkOwnerNotRequested(t *testing.T) {
	// "": an older tunneld or mode off (no owner object); "off" and an unknown
	// mode also count as not asked.
	for _, mode := range []string{"", "off", "audit"} {
		t.Run("mode="+mode, func(t *testing.T) {
			r := newOwnerRig(t, mode, "wh-api-test")
			f := &fakeIssuer{answers: []func(context.Context) (string, error){ret("", errors.New("must not be called"))}}
			link, err := r.link(t, f.fn)
			if err != nil || f.calls != 0 || link.Mode != "" || link.Ticket != "" || link.Absent != OwnerAbsentNotRequested {
				t.Fatalf("link %+v err %v calls %d", link, err, f.calls)
			}
			if got := r.edge.OwnerTickets(); len(got) != 1 || got[0] != "" {
				t.Fatalf("one whoami without a ticket, got %q", got)
			}
		})
	}
}

func TestLinkOwnerLinked(t *testing.T) {
	v := loadOwnerVectors(t)
	ticket := v.valid(t, "hostinger_numeric_sub")
	for _, mode := range []string{OwnerModeLog, OwnerModeRequire} {
		t.Run(mode, func(t *testing.T) {
			r := newOwnerRig(t, mode, v.Config.Issuer)
			f := &fakeIssuer{answers: []func(context.Context) (string, error){ret(ticket, nil)}}
			link, err := r.link(t, f.fn)
			if err != nil || !link.Linked() || link.Mode != mode || link.Ticket != ticket || link.Absent != "" ||
				link.ClientID != "123456" || link.OtherEnvironment {
				t.Fatalf("link %+v err %v", link, err)
			}
			// The connector passes the id and NotAfter it derived itself.
			if f.calls != 1 || f.tids[0] != r.creds.TunnelID || !f.expiry[0].Equal(r.creds.Leaf.NotAfter) {
				t.Fatalf("calls %d tids %v expiry %v", f.calls, f.tids, f.expiry)
			}
			want := ownerBudgetLog
			if mode == OwnerModeRequire {
				want = ownerBudgetRequire
			}
			if len(f.budgets) != 1 || f.budgets[0] > want || f.budgets[0] < want-time.Second {
				t.Fatalf("deadline %v, want about %v", f.budgets, want)
			}
			if got := r.edge.OwnerTickets(); len(got) != 2 || got[0] != "" || got[1] != ticket {
				t.Fatalf("whoami tickets %q: the first without, the second with the ticket", got)
			}
		})
	}
}

func TestLinkOwnerLogModeReasons(t *testing.T) {
	cases := []struct {
		name   string
		fn     OwnerTicketFunc
		answer func(context.Context) (string, error)
		absent string
	}{
		{name: "nil func", absent: OwnerAbsentUnsupported},
		{name: "no token", answer: ret("", ErrOwnerNoToken), absent: OwnerAbsentNoToken},
		{name: "wrapped no token", answer: ret("", fmt.Errorf("credentials: %w", ErrOwnerNoToken)), absent: OwnerAbsentNoToken},
		{name: "opted out", answer: ret("", ErrOwnerOptedOut), absent: OwnerAbsentOptedOut},
		{name: "temporary", answer: ret("", ErrOwnerTemporary), absent: OwnerAbsentFetchFailed},
		{name: "4xx", answer: ret("", errors.New("the API answered 422")), absent: OwnerAbsentFetchFailed},
		{name: "not a JWS", answer: ret("a b\r\nc", nil), absent: OwnerAbsentFetchFailed},
		{name: "empty ticket", answer: ret("", nil), absent: OwnerAbsentFetchFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newOwnerRig(t, OwnerModeLog, "wh-api-test")
			var f *fakeIssuer
			fn := tc.fn
			if tc.answer != nil {
				f = &fakeIssuer{answers: []func(context.Context) (string, error){tc.answer}}
				fn = f.fn
			}
			link, err := r.link(t, fn)
			if err != nil || link.Mode != OwnerModeLog || link.Ticket != "" || link.Absent != tc.absent || link.Linked() {
				t.Fatalf("link %+v err %v", link, err)
			}
			// Log mode: one call at most, never a retry, no second whoami.
			if f != nil && f.calls != 1 {
				t.Fatalf("calls %d", f.calls)
			}
			if got := r.edge.OwnerTickets(); len(got) != 1 {
				t.Fatalf("no second whoami without a ticket, got %q", got)
			}
		})
	}
}

func TestLinkOwnerRequireRetriesOnlyTemporary(t *testing.T) {
	v := loadOwnerVectors(t)
	ticket := v.valid(t, "niaga_sub")
	cases := []struct {
		name    string
		answers []func(context.Context) (string, error)
		calls   int
		linked  bool
		absent  string
	}{
		{"temporary then ok", []func(context.Context) (string, error){ret("", ErrOwnerTemporary), ret(ticket, nil)}, 2, true, ""},
		{"temporary twice", []func(context.Context) (string, error){ret("", ErrOwnerTemporary)}, 2, false, OwnerAbsentFetchFailed},
		{"no token", []func(context.Context) (string, error){ret("", ErrOwnerNoToken), ret(ticket, nil)}, 1, false, OwnerAbsentNoToken},
		{"opted out", []func(context.Context) (string, error){ret("", ErrOwnerOptedOut), ret(ticket, nil)}, 1, false, OwnerAbsentOptedOut},
		{"4xx", []func(context.Context) (string, error){ret("", errors.New("429")), ret(ticket, nil)}, 1, false, OwnerAbsentFetchFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newOwnerRig(t, OwnerModeRequire, v.Config.Issuer)
			f := &fakeIssuer{answers: tc.answers}
			link, err := r.link(t, f.fn)
			if f.calls != tc.calls || link.Linked() != tc.linked || link.Absent != tc.absent {
				t.Fatalf("calls %d link %+v err %v", f.calls, link, err)
			}
			if tc.linked != (err == nil) || (err != nil && !errors.Is(err, ErrOwnerRequired)) {
				t.Fatalf("err %v", err)
			}
		})
	}
	t.Run("nil func", func(t *testing.T) {
		r := newOwnerRig(t, OwnerModeRequire, v.Config.Issuer)
		link, err := r.link(t, nil)
		if !errors.Is(err, ErrOwnerRequired) || link.Absent != OwnerAbsentUnsupported {
			t.Fatalf("link %+v err %v", link, err)
		}
	})
}

// A callback that ignores its ctx still ends the step at the deadline, and
// in require mode that timeout is temporary: one retry.
func TestLinkOwnerDeadline(t *testing.T) {
	oldLog, oldReq := ownerBudgetLog, ownerBudgetRequire
	ownerBudgetLog, ownerBudgetRequire = 50*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { ownerBudgetLog, ownerBudgetRequire = oldLog, oldReq })
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	stuck := func(context.Context) (string, error) { <-release; return "", nil }
	for _, mode := range []string{OwnerModeLog, OwnerModeRequire} {
		t.Run(mode, func(t *testing.T) {
			r := newOwnerRig(t, mode, "wh-api-test")
			f := &fakeIssuer{answers: []func(context.Context) (string, error){stuck}}
			start := time.Now()
			link, err := r.link(t, f.fn)
			want := 1
			if mode == OwnerModeRequire {
				want = 2
			}
			f.mu.Lock()
			calls := f.calls
			f.mu.Unlock()
			if calls != want || link.Absent != OwnerAbsentFetchFailed || time.Since(start) > 5*time.Second {
				t.Fatalf("calls %d link %+v after %v", calls, link, time.Since(start))
			}
			if (mode == OwnerModeRequire) != errors.Is(err, ErrOwnerRequired) {
				t.Fatalf("err %v", err)
			}
		})
	}
}

func TestLinkOwnerVerdicts(t *testing.T) {
	v := loadOwnerVectors(t)
	cases := []struct {
		name, vector, reason string
		other                bool
	}{
		// The ticket's iss (wh-api) is not the edge's issuer (wh-api-test).
		{"other environment", "wrong_iss", "bad_claims", true},
		// Same iss, unknown key: a key problem, not another environment.
		{"unknown kid", "unknown_kid", "unknown_kid", false},
		{"tid mismatch", "tid_mismatch", "tid_mismatch", false},
	}
	for _, tc := range cases {
		for _, mode := range []string{OwnerModeLog, OwnerModeRequire} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				ticket := v.invalid(t, tc.vector)
				r := newOwnerRig(t, mode, v.Config.Issuer)
				r.edge.OwnerVerdict = func(got string) (string, string, string) {
					if got != ticket {
						return "invalid", "malformed", ""
					}
					return "invalid", tc.reason, ""
				}
				f := &fakeIssuer{answers: []func(context.Context) (string, error){ret(ticket, nil)}}
				link, err := r.link(t, f.fn)
				if link.Linked() || link.Status != "invalid" || link.Reason != tc.reason || link.OtherEnvironment != tc.other ||
					link.Ticket != ticket {
					t.Fatalf("link %+v", link)
				}
				if (mode == OwnerModeRequire) != errors.Is(err, ErrOwnerRequired) || (mode == OwnerModeLog && err != nil) {
					t.Fatalf("err %v", err)
				}
			})
		}
	}
}

func TestValidTicketShape(t *testing.T) {
	part := strings.Repeat("a", (maxOwnerTicketLen-2)/3)
	max := part + "." + part + "." + part + strings.Repeat("a", maxOwnerTicketLen-2-3*len(part))
	if len(max) != maxOwnerTicketLen || !validTicket(max) {
		t.Fatalf("a %d-byte ticket must pass", len(max))
	}
	for _, s := range []string{max + "a", "..", "a..c", ".b.c", "a.b.", "a.b", "a.b.c.d", "a.b!.c"} {
		if validTicket(s) {
			t.Errorf("%.20q (len %d) accepted", s, len(s))
		}
	}
}

func TestTicketIssuer(t *testing.T) {
	v := loadOwnerVectors(t)
	for _, c := range v.Valid {
		if got := ticketIssuer(c.Ticket); got != c.Iss || !validTicket(c.Ticket) {
			t.Errorf("%s: iss %q, want %q", c.Name, got, c.Iss)
		}
	}
	if got := ticketIssuer(v.invalid(t, "wrong_iss")); got != "wh-api" {
		t.Errorf("wrong_iss: %q", got)
	}
	for _, s := range []string{"", "a.b", "a.!!!.c", "a.bm90IGpzb24.c"} {
		if got := ticketIssuer(s); got != "" {
			t.Errorf("%q: %q", s, got)
		}
	}
}

func TestOptionsOwnerValidated(t *testing.T) {
	c, err := creds.NewQuick([]string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range []OwnerLink{{Ticket: "a\nb.c.d"}, {Absent: "bogus"}} {
		s, err := creds.NewMemoryStore(c, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		cfg := config.Default()
		cfg.TunnelID = c.TunnelID
		if _, err := New(Options{Config: cfg, Credentials: s, Owner: o}); err == nil {
			t.Errorf("Owner %+v must be refused", o)
		}
	}
}
