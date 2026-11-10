//go:build !windows

package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/hostinger/hcdn-connector/internal/proto"
	"github.com/hostinger/hcdn-connector/internal/testedge"
	"github.com/hostinger/hcdn-connector/internal/testpki"
	"github.com/hostinger/hcdn-connector/pkg/localguard"
)

func TestRunWithoutAdminSocket(t *testing.T) {
	runAndStop(t, "ingress:\n  - service: http_status:404\n", nil)
}

// allow_local_ports reaches the guard of `run`: a listed local port is proxied.
func TestRunAllowLocalPorts(t *testing.T) {
	var ln net.Listener
	for _, p := range localguard.BlockedPorts() {
		if p.Number < 1024 || p.WarnOnly {
			continue
		}
		if l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p.Number)); err == nil {
			ln = l
			break
		}
	}
	if ln == nil {
		t.Skip("every listed port above 1023 is in use")
	}
	svc := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	svc.Listener.Close()
	svc.Listener = ln
	svc.Start()
	defer svc.Close()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	src := "allow_local_ports: [" + port + "]\ningress:\n  - hostname: app.example.com\n    service: " + svc.URL +
		"\n  - service: http_status:404\n"
	runAndStop(t, src, func(s *testedge.Session) {
		res := s.Get(t, "app.example.com", "/")
		res.Body.Close()
		if res.StatusCode != http.StatusTeapot {
			t.Errorf("allowed port %s: status %d, hcdn-error %q", port, res.StatusCode, res.Header.Get(proto.HdrError))
		}
	})
}

// runAndStop runs `run` against a test edge with extra config keys, calls
// during (if set) on the first session, then stops it with SIGTERM.
func runAndStop(t *testing.T, extra string, during func(*testedge.Session)) {
	t.Helper()
	ca := testpki.NewCA(t)
	edge := testedge.New(t, ca, "bnk", false)
	dir := t.TempDir()
	credsPath := ca.WriteCredentials(t, dir, tid, []string{"127.0.0.1"}, time.Now().Add(400*24*time.Hour))
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, ca.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yml")
	src := "tunnel_id: " + tid + "\ncredentials_file: " + credsPath + "\nserver_ca_file: " + caFile +
		"\nports: [" + strconv.Itoa(edge.Port()) + "]\nhome_pops: 1\nsessions_per_pop: 1\nadmin_socket: \"\"\nmetrics_addr: \"\"\n" +
		"log:\n  level: error\n" + extra
	if err := os.WriteFile(cfg, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var errOut bytes.Buffer
	code := make(chan int, 1)
	go func() { code <- cmdRun([]string{"--config", cfg}, &errOut) }()
	s := edge.WaitSession(t)
	if s.HelloErr != nil {
		t.Fatalf("hello: %v", s.HelloErr)
	}
	if during != nil {
		during(s)
	}
	// cmdRun has registered its handler by now, so SIGTERM reaches its channel.
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-code:
		if c != exitOK {
			t.Fatalf("run exit %d: %s", c, errOut.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("run did not stop on SIGTERM")
	}
}
