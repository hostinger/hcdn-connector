package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hostinger/hcdn-connector/internal/proto"
	"github.com/hostinger/hcdn-connector/internal/testedge"
	"github.com/hostinger/hcdn-connector/internal/testpki"
	"github.com/hostinger/hcdn-connector/pkg/connector"
)

type quickRun struct {
	edge        *testedge.Edge
	out, errOut syncBuffer
	code        chan int
	cancel      context.CancelFunc
}

// startQuick runs runQuick against a fake edge in the given owner mode.
func startQuick(t *testing.T, mode string, owner connector.OwnerTicketFunc) *quickRun {
	t.Helper()
	return startQuickEdge(t, mode, owner, nil)
}

// startQuickEdge is startQuick with setup (if set) run on the edge first.
func startQuickEdge(t *testing.T, mode string, owner connector.OwnerTicketFunc, setup func(*testedge.Edge)) *quickRun {
	t.Helper()
	ca := testpki.NewCA(t)
	r := &quickRun{edge: testedge.New(t, ca, "bnk", false), code: make(chan int, 1)}
	r.edge.SetQuickZone("hostingerpreview.dev")
	r.edge.OwnerMode, r.edge.OwnerIssuer = mode, "wh-api-test"
	if setup != nil {
		setup(r.edge)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, ca.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	f, ok := parseQuickFlags([]string{"--url", "http://127.0.0.1:1", "--log-level", "error",
		"--bootstrap", "127.0.0.1", "--server-ca-file", caFile, "--ports", strconv.Itoa(r.edge.Port())}, io.Discard)
	if !ok {
		t.Fatal("flags")
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() { r.code <- runQuick(ctx, f, owner, &r.out, &r.errOut) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.code:
		case <-time.After(20 * time.Second):
			t.Error("quick did not stop")
		}
	})
	return r
}

func (r *quickRun) wait(t *testing.T) int {
	t.Helper()
	select {
	case c := <-r.code:
		r.code <- c // for the cleanup
		return c
	case <-time.After(20 * time.Second):
		t.Fatal("quick did not stop")
		return -1
	}
}

func validOwnerTicket(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "pkg", "connector", "testdata", "owner_ticket.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Valid []struct{ Ticket string } `json:"valid"`
	}
	if err := json.Unmarshal(b, &v); err != nil || len(v.Valid) == 0 {
		t.Fatalf("vectors: %v", err)
	}
	return v.Valid[0].Ticket
}

// The standalone command has no ticket: mode off (or an older tunneld) sends
// not_requested, log mode sends unsupported. No owner line, one whoami.
func TestQuickStandaloneOwnerAbsent(t *testing.T) {
	for _, tc := range []struct{ mode, absent string }{
		{"", proto.OwnerAbsentNotRequested},
		{proto.OwnerModeLog, proto.OwnerAbsentUnsupported},
	} {
		t.Run("mode="+tc.mode, func(t *testing.T) {
			r := startQuick(t, tc.mode, nil)
			s := r.edge.WaitSession(t)
			if s.HelloErr != nil || s.Hello.Header.Get(proto.HdrOwnerAbsent) != tc.absent ||
				s.Hello.Header.Get(proto.HdrOwnerTicket) != "" || s.Hello.Header.Get(proto.HdrFeatures) != "ws,owner,visible" {
				t.Fatalf("hello: %v %v", s.HelloErr, s.Hello.Header)
			}
			if got := r.edge.OwnerTickets(); len(got) != 1 || got[0] != "" {
				t.Fatalf("whoami tickets %q", got)
			}
			r.cancel()
			if c := r.wait(t); c != exitOK || strings.Contains(r.out.String(), "linked") || strings.Contains(r.out.String(), "Linked") {
				t.Fatalf("exit %d: %q %q", c, r.out.String(), r.errOut.String())
			}
		})
	}
}

// With a callback, the ticket goes out on the second whoami and on every hello.
func TestQuickOwnerTicketOnWhoamiAndHello(t *testing.T) {
	ticket := validOwnerTicket(t)
	calls := 0
	r := startQuick(t, proto.OwnerModeLog, func(context.Context, string, time.Time) (string, error) {
		calls++
		return ticket, nil
	})
	s := r.edge.WaitSession(t)
	if s.HelloErr != nil || s.Hello.Header.Get(proto.HdrOwnerTicket) != ticket || s.Hello.Header.Get(proto.HdrOwnerAbsent) != "" {
		t.Fatalf("hello: %v %v", s.HelloErr, s.Hello.Header)
	}
	if got := r.edge.OwnerTickets(); len(got) != 2 || got[0] != "" || got[1] != ticket {
		t.Fatalf("whoami tickets %q", got)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(r.out.String(), "Linked to your Hostinger account.") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(r.out.String(), "Linked to your Hostinger account.") || calls != 1 {
		t.Fatalf("calls %d out %q", calls, r.out.String())
	}
	// A reconnect (two sessions per PoP, so the third is a redial) re-sends the
	// same ticket without a new issuer call or whoami.
	s2 := r.edge.WaitSession(t)
	s.Goaway(t, proto.ReasonDrain, 0)
	s.CC.Close()
	s3 := r.edge.WaitSession(t)
	for i, x := range []*testedge.Session{s2, s3} {
		if x.HelloErr != nil || x.Hello.Header.Get(proto.HdrOwnerTicket) != ticket {
			t.Fatalf("hello %d: %v %v", i+2, x.HelloErr, x.Hello.Header)
		}
	}
	if got := r.edge.OwnerTickets(); calls != 1 || len(got) != 2 {
		t.Fatalf("after a reconnect: calls %d whoami tickets %d", calls, len(got))
	}
}

func TestQuickOwnerLine(t *testing.T) {
	for _, tc := range []struct {
		l    connector.OwnerLink
		want string
	}{
		{connector.OwnerLink{Absent: connector.OwnerAbsentNotRequested}, ""},
		{connector.OwnerLink{Mode: "log", Ticket: "a.b.c", Status: "ok", ClientID: "1"}, "Linked to your Hostinger account."},
		{connector.OwnerLink{Mode: "log", Absent: connector.OwnerAbsentNoToken}, "Not linked to an account (no_token)."},
		{connector.OwnerLink{Mode: "log", Ticket: "a.b.c", Status: "invalid", Reason: "unknown_kid", OtherEnvironment: true},
			"Not linked to an account (ticket from another environment)."},
		{connector.OwnerLink{Mode: "log", Ticket: "a.b.c", Status: "invalid", Reason: "expired"}, "Not linked to an account (expired)."},
	} {
		if got := ownerLine(tc.l); got != tc.want {
			t.Errorf("%+v: %q, want %q", tc.l, got, tc.want)
		}
	}
}

// require mode without a ticket: exit 77 before any session, with a message
// that does not point the standalone binary at `hostinger login`.
func TestQuickRequireWithoutTicketExits77(t *testing.T) {
	r := startQuick(t, proto.OwnerModeRequire, nil)
	if c := r.wait(t); c != exitNoPerm {
		t.Fatalf("exit %d: %q", c, r.errOut.String())
	}
	if msg := r.errOut.String(); !strings.Contains(msg, quickSignIn) || strings.Contains(msg, "hostinger login") ||
		strings.Contains(msg, "taken down") {
		t.Fatalf("message %q", msg)
	}
	if r.edge.Dials.Load() != 0 || strings.Contains(r.out.String(), "https://") {
		t.Fatalf("no session and no URL in require mode without a ticket: dials %d out %q", r.edge.Dials.Load(), r.out.String())
	}
}

func TestQuickRequireRetriesTemporaryOnce(t *testing.T) {
	calls := 0
	r := startQuick(t, proto.OwnerModeRequire, func(context.Context, string, time.Time) (string, error) {
		calls++
		return "", connector.ErrOwnerTemporary
	})
	if c := r.wait(t); c != exitNoPerm || calls != 2 {
		t.Fatalf("exit %d calls %d: %q", c, calls, r.errOut.String())
	}
}

// The exit message follows the goaway reason, not the code.
func TestQuickGoawayExit(t *testing.T) {
	for _, tc := range []struct {
		reason string
		code   int
		want   string
		not    string
	}{
		{proto.ReasonRevoked, exitConfig, "this tunnel was taken down", quickSignIn},
		{proto.ReasonUnknownSerial, exitConfig, "no longer accepts this tunnel's certificate", "taken down"},
		{proto.ReasonOwnerRequired, exitNoPerm, quickSignIn, "taken down"},
	} {
		// Before hello the goaway comes before any URL: the same exit.
		for _, noHello := range []bool{false, true} {
			t.Run(tc.reason+map[bool]string{false: "", true: " before hello"}[noHello], func(t *testing.T) {
				r := startQuickEdge(t, "", nil, func(e *testedge.Edge) { e.NoHello = noHello })
				s := r.edge.WaitSession(t)
				if s.HelloErr != nil {
					t.Fatal(s.HelloErr)
				}
				s.Goaway(t, tc.reason, 0)
				c := r.wait(t)
				msg := r.errOut.String()
				if c != tc.code || !strings.Contains(msg, tc.want) || strings.Contains(msg, tc.not) || strings.Contains(msg, "hostinger login") {
					t.Fatalf("exit %d: %q", c, msg)
				}
				if noHello && strings.Contains(r.out.String(), "https://") {
					t.Fatalf("URL printed: %q", r.out.String())
				}
			})
		}
	}
}

// Control characters in the owner object never reach the terminal: a bad
// verdict on the second whoami leaves the run unlinked, a bad first whoami
// stops it.
func TestQuickWhoamiControlChars(t *testing.T) {
	const reason = "\x1b]52;c;eA==\a"
	ticket := validOwnerTicket(t)
	owner := func(context.Context, string, time.Time) (string, error) { return ticket, nil }
	clean := func(t *testing.T, r *quickRun) {
		t.Helper()
		if s := r.out.String() + r.errOut.String(); strings.ContainsAny(s, "\x1b\a") {
			t.Fatalf("raw control characters in quick output: %q", s)
		}
	}

	t.Run("second whoami", func(t *testing.T) {
		r := startQuickEdge(t, proto.OwnerModeLog, owner, func(e *testedge.Edge) {
			e.OwnerVerdict = func(string) (string, string, string) { return "invalid", reason, "" }
		})
		if s := r.edge.WaitSession(t); s.HelloErr != nil {
			t.Fatal(s.HelloErr)
		}
		const want = "Not linked to an account (no verdict from the edge)."
		deadline := time.Now().Add(5 * time.Second)
		for !strings.Contains(r.out.String(), want) && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		r.cancel()
		if c := r.wait(t); c != exitOK || !strings.Contains(r.out.String(), want) {
			t.Fatalf("exit %d: %q %q", c, r.out.String(), r.errOut.String())
		}
		clean(t, r)
	})

	t.Run("first whoami", func(t *testing.T) {
		r := startQuickEdge(t, proto.OwnerModeLog, owner, func(e *testedge.Edge) {
			e.WhoamiRaw = []byte(`{"tunnel_id":"018f2c3a-7b1e-8c4d-9a2b-3c4d5e6f7a8b","cert_serial":"1f","pop":"bnk",` +
				`"node":"bnk-edge1","class":"quick","hostname":"018f2c3a7b1e8c4d9a2b3c4d5e6f7a8b.hostingerpreview.dev",` +
				`"owner":{"mode":"log","issuer":"wh-api-test","reason":"\u001b]52;c;eA==\u0007"}}`)
		})
		if c := r.wait(t); c != exitFailure || !strings.Contains(r.errOut.String(), "the edge refused the quick tunnel") {
			t.Fatalf("exit %d: %q %q", c, r.out.String(), r.errOut.String())
		}
		clean(t, r)
	})
}

// quickAgainst runs quick against a TLS listener on 127.0.0.1 that presents
// cert, dialled by the name bootstrap, and returns its exit code and output.
// serve gets each conn after the handshake (nil: close it).
func quickAgainst(t *testing.T, ca *testpki.CA, cert tls.Certificate, bootstrap string, serve func(*tls.Conn)) (int, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequestClientCert,
					NextProtos: []string{proto.ALPNAPI}})
				if tc.Handshake() == nil && serve != nil {
					serve(tc)
				}
			}()
		}
	}()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, ca.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	f, ok := parseQuickFlags([]string{"--url", "http://127.0.0.1:1", "--log-level", "error",
		"--bootstrap", bootstrap, "--server-ca-file", caFile, "--ports", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)}, io.Discard)
	if !ok {
		t.Fatal("flags")
	}
	var out, errOut bytes.Buffer
	code := runQuick(context.Background(), f, nil, &out, &errOut)
	return code, out.String() + errOut.String()
}

// Edge-supplied bytes in a quick start error reach the terminal escaped.
func TestQuickStartErrorControlChars(t *testing.T) {
	ca := testpki.NewCA(t)
	check := func(t *testing.T, code int, s, want string) {
		t.Helper()
		if code != exitFailure || !strings.Contains(s, "the edge refused the quick tunnel") || !strings.Contains(s, want) {
			t.Fatalf("exit %d: %q", code, s)
		}
		if strings.ContainsAny(s, "\x1b\a") {
			t.Fatalf("raw control characters in quick output: %q", s)
		}
	}

	t.Run("certificate name", func(t *testing.T) {
		// Go accepts any ASCII in a dNSName; HostnameError lists the names.
		cert := ca.IssueServer(t, "x\x1b]52;c;eA==\a.example")
		code, s := quickAgainst(t, ca, cert, "localhost", nil)
		check(t, code, s, `is valid for x\x1b]52;c;eA==\x07.example`)
	})

	t.Run("whoami header", func(t *testing.T) {
		// net/http quotes the line itself today; this guards the print site.
		code, s := quickAgainst(t, ca, ca.IssueServer(t, "localhost"), "127.0.0.1", func(tc *tls.Conn) {
			if _, err := http.ReadRequest(bufio.NewReader(tc)); err == nil {
				io.WriteString(tc, "HTTP/1.1 200 OK\r\n\x1b]0;pwned\x07\x1b[2J: x\r\nContent-Length: 0\r\n\r\n")
			}
		})
		check(t, code, s, "malformed MIME header line")
	})
}
