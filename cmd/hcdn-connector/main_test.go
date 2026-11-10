package main

import (
	"bytes"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hostinger/hcdn-connector/internal/session"
	"github.com/hostinger/hcdn-connector/internal/testedge"
	"github.com/hostinger/hcdn-connector/internal/testpki"
)

const tid = "3f9c2a7e-0b3e-4d0a-9d0a-1c8f5e7b2a11"

func writeConfig(t *testing.T, dir, credsPath, service string) string {
	t.Helper()
	cfg := `
tunnel_id: ` + tid + `
credentials_file: ` + credsPath + `
ingress:
  - hostname: shop.example.com
    service: ` + service + `
  - service: http_status:404
admin_socket: ` + filepath.Join(dir, "admin.sock") + `
metrics_addr: ""
`
	p := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(p, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBuildInfoVersion(t *testing.T) {
	for _, tc := range []struct {
		info *debug.BuildInfo
		want string
	}{
		{nil, "devel"},
		{&debug.BuildInfo{}, "devel"},
		{&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, "devel"},
		{&debug.BuildInfo{Main: debug.Module{Version: "v0.2.0"}}, "0.2.0"},
		{&debug.BuildInfo{Main: debug.Module{Version: "v0.2.1-0.20261110093000-0123456789ab"}}, "0.2.1-0.20261110093000-0123456789ab"},
	} {
		if got := buildInfoVersion(tc.info); got != tc.want {
			t.Errorf("buildInfoVersion(%+v) = %q, want %q", tc.info, got, tc.want)
		}
	}
}

func TestVersionAndUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	// go test builds have no module version and no -ldflags.
	if code := run([]string{"version"}, &out, &errOut); code != exitOK || !strings.HasPrefix(out.String(), "hcdn-connector devel\n") {
		t.Fatalf("version: %d %q", code, out.String())
	}
	if code := run(nil, &out, &errOut); code != exitUsage {
		t.Fatal("no args must be a usage error")
	}
	if code := run([]string{"bogus"}, &out, &errOut); code != exitUsage {
		t.Fatal("unknown command must be a usage error")
	}
}

func TestCheck(t *testing.T) {
	ca := testpki.NewCA(t)
	dir := t.TempDir()
	credsPath := ca.WriteCredentials(t, dir, tid, []string{"bnk.tunnel.example"}, time.Now().Add(10*24*time.Hour))
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer svc.Close()

	var out, errOut bytes.Buffer
	code := run([]string{"check", "--config", writeConfig(t, dir, credsPath, svc.URL)}, &out, &errOut)
	if code != exitOK {
		t.Fatalf("check exit %d\n%s%s", code, out.String(), errOut.String())
	}
	s := out.String()
	if !strings.Contains(s, "OK   config") || !strings.Contains(s, "WARN credentials") || !strings.Contains(s, "OK   shop.example.com") || !strings.Contains(s, "(catch-all)") {
		t.Fatalf("check output:\n%s", s)
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "http://" + ln.Addr().String()
	ln.Close()
	out.Reset()
	code = run([]string{"check", "--config", writeConfig(t, dir, credsPath, dead)}, &out, &errOut)
	if code != exitFailure || !strings.Contains(out.String(), "FAIL shop.example.com") || !strings.Contains(out.String(), "service_unreachable") {
		t.Fatalf("check unreachable: %d\n%s", code, out.String())
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(credsPath, 0o644); err != nil {
			t.Fatal(err)
		}
		errOut.Reset()
		code = run([]string{"check", "--config", writeConfig(t, dir, credsPath, svc.URL)}, &out, &errOut)
		if code != exitConfig || !strings.Contains(errOut.String(), "group/world readable") {
			t.Fatalf("check bad perms: %d %s", code, errOut.String())
		}
	}

	// Missing credentials: config passes, credentials step fails with a clear hint.
	out.Reset()
	errOut.Reset()
	code = run([]string{"check", "--config", writeConfig(t, dir, filepath.Join(dir, "missing.json"), svc.URL)}, &out, &errOut)
	if code != exitConfig || !strings.Contains(out.String(), "OK   config") ||
		!strings.Contains(errOut.String(), "FAIL credentials") || !strings.Contains(errOut.String(), "not found") {
		t.Fatalf("check missing creds: %d\n%s%s", code, out.String(), errOut.String())
	}
}

// check --whoami fails the whoami row on a reply with control characters
// and prints none of them.
func TestCheckWhoamiControlChars(t *testing.T) {
	ca := testpki.NewCA(t)
	edge := testedge.New(t, ca, "bnk", false)
	edge.WhoamiRaw = []byte(`{"tunnel_id":"` + tid + `","cert_serial":"1f","days_left":100,"pop":"bnk","node":"\u001b[2Jx"}`)
	dir := t.TempDir()
	credsPath := ca.WriteCredentials(t, dir, tid, []string{"127.0.0.1"}, time.Now().Add(400*24*time.Hour))
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, ca.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yml")
	src := "tunnel_id: " + tid + "\ncredentials_file: " + credsPath + "\nserver_ca_file: " + caFile +
		"\nports: [" + strconv.Itoa(edge.Port()) + "]\nadmin_socket: \"\"\nmetrics_addr: \"\"\n" +
		"ingress:\n  - service: http_status:404\n"
	if err := os.WriteFile(cfg, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"check", "--config", cfg, "--whoami"}, &out, &errOut)
	if code != exitFailure || !strings.Contains(out.String(), "FAIL whoami: ") || !strings.Contains(out.String(), "non-printable") {
		t.Fatalf("check exit %d\n%s%s", code, out.String(), errOut.String())
	}
	if s := out.String() + errOut.String(); strings.ContainsAny(s, "\x1b\a") {
		t.Fatalf("raw control characters in check output: %q", s)
	}
}

// check escapes the ingress row of an https origin whose certificate
// names hold control characters.
func TestCheckOriginCertControlChars(t *testing.T) {
	ca := testpki.NewCA(t)
	dir := t.TempDir()
	credsPath := ca.WriteCredentials(t, dir, tid, []string{"bnk.tunnel.example"}, time.Now().Add(400*24*time.Hour))
	svc := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	svc.TLS = &tls.Config{Certificates: []tls.Certificate{ca.IssueServer(t, "x\x1b]52;c;eA==\a.example")}}
	svc.StartTLS()
	defer svc.Close()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, ca.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yml")
	src := "tunnel_id: " + tid + "\ncredentials_file: " + credsPath + "\nadmin_socket: \"\"\nmetrics_addr: \"\"\n" +
		"ingress:\n  - hostname: shop.example.com\n    service: " + svc.URL +
		"\n    origin_request:\n      ca_file: " + caFile + "\n      tls_server_name: origin.test\n" +
		"  - service: http_status:404\n"
	if err := os.WriteFile(cfg, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"check", "--config", cfg}, &out, &errOut)
	s := out.String() + errOut.String()
	if code != exitFailure || !strings.Contains(s, "FAIL shop.example.com") || !strings.Contains(s, `x\x1b]52;c;eA==\x07.example`) {
		t.Fatalf("check exit %d\n%s", code, s)
	}
	if strings.ContainsAny(s, "\x1b\a") {
		t.Fatalf("raw control characters in check output: %q", s)
	}
}

// allow_local_ports reaches the local port guard: check stops refusing the port.
func TestCheckAllowLocalPorts(t *testing.T) {
	ca := testpki.NewCA(t)
	dir := t.TempDir()
	credsPath := ca.WriteCredentials(t, dir, tid, []string{"bnk.tunnel.example"}, time.Now().Add(400*24*time.Hour))
	cfg := writeConfig(t, dir, credsPath, "http://127.0.0.1:6379")

	var out, errOut bytes.Buffer
	if code := run([]string{"check", "--config", cfg}, &out, &errOut); code != exitFailure || !strings.Contains(out.String(), "port 6379 is not shared") {
		t.Fatalf("guarded: %d\n%s%s", code, out.String(), errOut.String())
	}

	b, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, append(b, "allow_local_ports: [6379]\n"...), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	run([]string{"check", "--config", cfg}, &out, &errOut)
	if s := out.String() + errOut.String(); !strings.Contains(s, "OK   config") || strings.Contains(s, "is not shared") {
		t.Fatalf("allow_local_ports did not opt 6379 out:\n%s", s)
	}
}

func TestCSRCommand(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	key, csr := filepath.Join(dir, "k.pem"), filepath.Join(dir, "c.pem")
	if code := run([]string{"csr", "--out", key + "," + csr, "--tunnel-id", tid}, &out, &errOut); code != exitOK {
		t.Fatalf("csr: %d %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "BEGIN CERTIFICATE REQUEST") {
		t.Fatal("CSR not printed")
	}
	if _, err := os.Stat(key); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"csr", "--out", key, "--tunnel-id", tid}, &out, &errOut); code != exitUsage {
		t.Fatal("single --out path must be a usage error")
	}
	if code := run([]string{"csr", "--out", key + "," + csr, "--tunnel-id", "nope"}, &out, &errOut); code != exitUsage {
		t.Fatal("bad tunnel id must be a usage error")
	}
}

func TestPrintStatus(t *testing.T) {
	var out bytes.Buffer
	printStatus(&out, session.Status{
		Version: "0.1.0", ConnectorID: "abc", TunnelID: tid, StartedAt: time.Now().Add(-time.Hour), CertSerial: "1f", CertDaysLeft: 200,
		Selection: session.Selection{Pops: []string{"bnk"}, Reason: "bnk: fastest", Trigger: "startup", At: time.Now(), PopsGen: 41, Source: "fra.tunnel.example",
			Probes: []session.ProbeRow{{Pop: "bnk", Endpoint: "bnk.tunnel.example", Allowed: true, Selected: true, Port: 7844, RTTms: 12.3},
				{Pop: "mum", Endpoint: "mum.tunnel.example", Allowed: true, Error: "timeout"}}},
		Pops: []session.SupervisorInfo{{Pop: "bnk", Endpoint: "bnk.tunnel.example", Target: 2, Ready: 1,
			Sessions: []session.SessionInfo{{Slot: 0, State: session.StateReady, Addr: "2001:db8::1", Port: 7844, Transport: "7844", EdgeNode: "edge1", Since: time.Now(), Inflight: 1, MaxInflight: 512},
				{Slot: 1, State: session.StateConnecting}}}},
		LastErrors: []session.ErrorEntry{{Time: time.Now(), Level: "WARN", Message: "dial failed"}},
	})
	s := out.String()
	for _, want := range []string{"selection: bnk", "POP", "RTT_MS", "12.3", "timeout", "ready", "connecting", "1/512", "dial failed"} {
		if !strings.Contains(s, want) {
			t.Fatalf("status output lacks %q:\n%s", want, s)
		}
	}
}

func TestStatusWithoutSocket(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"status", "--socket", filepath.Join(t.TempDir(), "none.sock")}, &out, &errOut); code != exitFailure {
		t.Fatalf("status without a daemon: %d", code)
	}
}

func TestStatusAdminSocketDisabled(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yml")
	src := "tunnel_id: " + tid + "\ncredentials_file: x\nadmin_socket: \"\"\ningress:\n  - service: http_status:404\n"
	if err := os.WriteFile(cfg, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"status", "--config", cfg}, &out, &errOut); code != exitFailure ||
		!strings.Contains(errOut.String(), "admin socket disabled in config") {
		t.Fatalf("status with admin_socket \"\": %d %q", code, errOut.String())
	}
}
