package main

import (
	"bytes"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hostinger/hcdn-connector/internal/session"
	"github.com/hostinger/hcdn-connector/internal/testpki"
	"github.com/hostinger/hcdn-connector/pkg/config"
	"github.com/hostinger/hcdn-connector/pkg/connector"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden")

// The goldens pin the Linux output; other OSes differ only in the default paths.
func linuxPaths(s string) string {
	s = strings.ReplaceAll(s, config.DefaultConfigPath, "/etc/hcdn-connector/config.yml")
	return strings.ReplaceAll(s, config.DefaultAdminSocket, "/run/hcdn-connector/admin.sock")
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run go test -update)", err)
	}
	if got != string(want) {
		t.Fatalf("%s differs from %s\n--- got\n%s\n--- want\n%s", name, p, got, want)
	}
}

func TestGoldenUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	run(nil, &out, &errOut)
	golden(t, "usage", linuxPaths(errOut.String()))
	out.Reset()
	run([]string{"help"}, &out, &errOut)
	golden(t, "usage", linuxPaths(out.String()))
}

func TestGoldenVersion(t *testing.T) {
	oldV, oldC, oldD := version, commit, date
	version, commit, date = "0.1.0", "abc1234", "2026-10-01T00:00:00Z"
	t.Cleanup(func() { version, commit, date = oldV, oldC, oldD })
	var out bytes.Buffer
	run([]string{"version"}, &out, &out)
	s := strings.Replace(out.String(), runtime.Version()+" "+runtime.GOOS+"/"+runtime.GOARCH, "GO OS/ARCH", 1)
	golden(t, "version", s)
}

var serialRe = regexp.MustCompile(`serial [0-9a-f]+`)

func TestGoldenCheck(t *testing.T) {
	ca := testpki.NewCA(t)
	dir := t.TempDir()
	credsPath := ca.WriteCredentials(t, dir, tid, []string{"bnk.tunnel.example"}, time.Now().Add(10*24*time.Hour))
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer svc.Close()
	var out, errOut bytes.Buffer
	if code := run([]string{"check", "--config", writeConfig(t, dir, credsPath, svc.URL)}, &out, &errOut); code != exitOK {
		t.Fatalf("check exit %d\n%s%s", code, out.String(), errOut.String())
	}
	s := strings.ReplaceAll(out.String(), dir, "$DIR")
	s = strings.ReplaceAll(s, svc.URL, "$SVC")
	s = serialRe.ReplaceAllLiteralString(filepath.ToSlash(s), "serial $SERIAL")
	golden(t, "check", s)
}

// Every row format, including the FAIL and whoami rows that need a broken service or a real edge.
func TestGoldenCheckRows(t *testing.T) {
	var out bytes.Buffer
	ok := printCheckRows(&out, []connector.CheckRow{
		{Kind: connector.CheckIngress, Name: "shop.example.com", Target: "http://127.0.0.1:8080", OK: true},
		{Kind: connector.CheckIngress, Name: "api.example.com", Target: "https://10.0.0.5:8443",
			Err: "dial tcp 10.0.0.5:8443: connect: connection refused", Class: "service_unreachable"},
		{Kind: connector.CheckIngress, Name: connector.CatchAllName, Target: "http_status:404", OK: true},
		{Kind: connector.CheckWhoami, Name: "whoami", OK: true,
			Target: "via bnk.tunnel.example: tunnel " + tid + " serial 1f days_left 200 pop bnk node pop1-edge1"},
		{Kind: connector.CheckWhoami, Name: "whoami", Err: "no bootstrap endpoint answered"},
	})
	if ok {
		t.Fatal("a FAIL row must fail the check")
	}
	golden(t, "check_rows", out.String())
}

func TestGoldenStatus(t *testing.T) {
	oldLocal := time.Local
	time.Local = time.UTC
	t.Cleanup(func() { time.Local = oldLocal })
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	var out bytes.Buffer
	printStatusAt(&out, session.Status{
		Version: "0.1.1", ConnectorID: "c0ffee", TunnelID: tid, StartedAt: now.Add(-90 * time.Minute), CertSerial: "1f", CertDaysLeft: 200,
		GlobalPauseUntil: now.Add(5 * time.Minute),
		Selection: session.Selection{Pops: []string{"bnk", "fra"}, Reason: "bnk: fastest; fra: second region", Trigger: "startup",
			At: now.Add(-time.Hour), PopsGen: 41, Source: "fra.tunnel.example",
			Probes: []session.ProbeRow{
				{Pop: "bnk", Endpoint: "bnk.tunnel.example", Region: "eu-north", Allowed: true, Pinned: true, Selected: true, Port: 7844, RTTms: 12.3},
				{Pop: "fra", Endpoint: "fra.tunnel.example", Region: "eu-central", Allowed: true, Selected: true, Port: 443, RTTms: 20},
				{Pop: "mum", Endpoint: "mum.tunnel.example", Region: "ap-south", Allowed: true, Error: "timeout"},
				{Pop: "phx", Endpoint: "phx.tunnel.example", Region: "us-west"},
			}},
		Pops: []session.SupervisorInfo{
			{Pop: "bnk", Endpoint: "bnk.tunnel.example", Target: 2, Ready: 1, Draining: 1,
				Sessions: []session.SessionInfo{
					{Slot: 0, State: session.StateReady, Addr: "2001:db8::1", Port: 7844, Transport: "7844", EdgeNode: "pop1-edge1", Since: now.Add(-42 * time.Second), Inflight: 1, MaxInflight: 512},
					{Slot: 1, State: session.StateConnecting}}},
			{Pop: "fra", Endpoint: "fra.tunnel.example", Target: 2, PausedUntil: now.Add(time.Minute), PauseReason: "cap_exceeded",
				LastError: "dial tcp: connection refused", LastErrorAt: now.Add(-3 * time.Second),
				Sessions: []session.SessionInfo{{Slot: 0, State: session.StatePaused}, {Slot: 1}}},
		},
		LastErrors: []session.ErrorEntry{{Time: now.Add(-10 * time.Second), Level: "WARN", Message: "dial failed pop=fra"}},
	}, now)
	golden(t, "status", out.String())
}
