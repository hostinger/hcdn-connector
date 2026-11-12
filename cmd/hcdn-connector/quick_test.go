package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hostinger/hcdn-connector/internal/testedge"
	"github.com/hostinger/hcdn-connector/internal/testpki"
	"github.com/hostinger/hcdn-connector/pkg/connector"
)

// syncBuffer: runQuick writes from its goroutine while the test reads.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestQuickServesTheDerivedHostname(t *testing.T) {
	ca := testpki.NewCA(t)
	edge := testedge.New(t, ca, "bnk", false)
	edge.SetQuickZone("hostingerpreview.dev")
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "host="+r.Host) }))
	defer svc.Close()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, ca.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	f, ok := parseQuickFlags([]string{"--url", svc.URL, "--host-header", "localhost", "--log-level", "error",
		"--bootstrap", "127.0.0.1", "--server-ca-file", caFile, "--ports", strconv.Itoa(edge.Port())}, io.Discard)
	if !ok {
		t.Fatal("flags")
	}
	var out, errOut syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	code := make(chan int, 1)
	go func() { code <- runQuick(ctx, f, nil, &out, &errOut) }()

	s := edge.WaitSession(t)
	if s.HelloErr != nil {
		t.Fatalf("hello: %v", s.HelloErr)
	}
	var host string
	re := regexp.MustCompile(`https://([0-9a-f]{12}8[0-9a-f]{3}[89ab][0-9a-f]{15}\.hostingerpreview\.dev)\n`)
	deadline := time.Now().Add(5 * time.Second)
	for host == "" && time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(out.String()); m != nil {
			host = m[1]
		}
		time.Sleep(10 * time.Millisecond)
	}
	if host == "" {
		t.Fatalf("no URL printed: %q %q", out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "Expires ") {
		t.Fatalf("no expiry line: %q", out.String())
	}
	res := s.Get(t, host, "/")
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(body) != "host=localhost" {
		t.Fatalf("got %d %q", res.StatusCode, body)
	}
	res = s.Get(t, "other.hostingerpreview.dev", "/")
	res.Body.Close()
	if res.StatusCode != 404 {
		t.Fatalf("another host must hit the catch-all 404, got %d", res.StatusCode)
	}
	cancel()
	select {
	case c := <-code:
		if c != exitOK {
			t.Fatalf("exit %d: %s", c, errOut.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("quick did not stop")
	}
}

func TestQuickRefusesAnEdgeWithoutQuickClass(t *testing.T) {
	ca := testpki.NewCA(t)
	// No QuickZone: like tunneld < 0.3.0, the handshake refuses the self-signed leaf.
	edge := testedge.New(t, ca, "bnk", false)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, ca.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	f, _ := parseQuickFlags([]string{"--url", "http://127.0.0.1:1", "--bootstrap", "127.0.0.1",
		"--server-ca-file", caFile, "--ports", strconv.Itoa(edge.Port())}, io.Discard)
	var out, errOut syncBuffer
	if c := runQuick(context.Background(), f, nil, &out, &errOut); c != exitFailure || !strings.Contains(errOut.String(), "refused the quick tunnel") {
		t.Fatalf("exit %d: %q", c, errOut.String())
	}
}

func TestQuickReportsABlockedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, testpki.NewCA(t).PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	f, _ := parseQuickFlags([]string{"--url", "http://127.0.0.1:1", "--bootstrap", "127.0.0.1",
		"--server-ca-file", caFile, "--ports", strconv.Itoa(port)}, io.Discard)
	var out, errOut syncBuffer
	if c := runQuick(context.Background(), f, nil, &out, &errOut); c != exitFailure || !strings.Contains(errOut.String(), "is blocked on this network") {
		t.Fatalf("exit %d: %q", c, errOut.String())
	}
}

func TestQuickCancelledDuringWhoami(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, testpki.NewCA(t).PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	f, _ := parseQuickFlags([]string{"--url", "http://127.0.0.1:1", "--log-level", "error", "--bootstrap", "127.0.0.1",
		"--server-ca-file", caFile, "--ports", "1"}, io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errOut syncBuffer
	if c := runQuick(ctx, f, nil, &out, &errOut); c != exitOK || errOut.String() != "" {
		t.Fatalf("Ctrl-C before Whoami ends must stop cleanly: exit %d %q", c, errOut.String())
	}
}

func TestQuickFlags(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--ports", "x", "--url", "http://a"},
		{"--ports", "0", "--url", "http://a"},
		{"--ports", "70000", "--url", "http://a"},
		{"--bootstrap", "a,,b", "--url", "http://a"},
		{"--bootstrap", "a,", "--url", "http://a"},
		{"--url", "http://a", "extra"},
		{"--log-level", "verbose", "--url", "http://a"},
	} {
		if _, ok := parseQuickFlags(args, io.Discard); ok {
			t.Errorf("%v must be a usage error", args)
		}
	}
	f, ok := parseQuickFlags([]string{"--url", "http://localhost:8080"}, io.Discard)
	if !ok || len(f.ports) != 1 || f.ports[0] != 7844 || f.bootstrap != quickBootstrap ||
		strings.Join(f.bootstrapAddrs, ",") != quickBootstrap {
		t.Fatalf("defaults: %+v", f)
	}
	if want := strings.Join(connector.DefaultQuickBootstrap(), ","); quickBootstrap != want {
		t.Fatalf("quickBootstrap %q, want the library default %q", quickBootstrap, want)
	}
	f, ok = parseQuickFlags([]string{"--url", "http://a", "--bootstrap", "a, b", "--ports", " 443 , 7844"}, io.Discard)
	if !ok || strings.Join(f.bootstrapAddrs, "|") != "a|b" || len(f.ports) != 2 || f.ports[0] != 443 {
		t.Fatalf("trimmed lists: %+v", f)
	}
	var errOut bytes.Buffer
	if code := run([]string{"quick"}, io.Discard, &errOut); code != exitUsage || strings.Contains(errOut.String(), "bootstrap") {
		t.Fatalf("usage must hide the staging flags: %d %q", code, errOut.String())
	}
}

// A sensitive local port is a usage error before any edge call: the edge
// port is closed, so reaching it would print "is blocked on this network".
func TestQuickRefusesASensitiveLocalPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	f, _ := parseQuickFlags([]string{"--url", "http://0:22", "--bootstrap", "127.0.0.1", "--ports", strconv.Itoa(port)}, io.Discard)
	var out, errOut syncBuffer
	c := runQuick(context.Background(), f, nil, &out, &errOut)
	want := "hcdn-connector: --url http://0:22: port 22 is not shared: it is the usual port of SSH, which must not be reachable from the internet\n"
	if c != exitUsage || errOut.String() != want || out.String() != "" {
		t.Fatalf("exit %d stdout %q stderr %q; want %d, %q", c, out.String(), errOut.String(), exitUsage, want)
	}
}
