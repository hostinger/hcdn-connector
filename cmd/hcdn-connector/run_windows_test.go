package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/hostinger/hcdn-connector/internal/proto"
	"github.com/hostinger/hcdn-connector/internal/testedge"
	"github.com/hostinger/hcdn-connector/internal/testpki"
)

// A process cannot send itself a console event, so these tests run the
// connector in a child: the test binary, which acts as hcdn-connector when
// helperEnv is set. The child gets its own process group, and the test
// stops it with Ctrl-Break, the event a user's Ctrl-Break sends.
const helperEnv = "HCDN_CONNECTOR_TEST_AS_BINARY"

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) != "" {
		os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

// child is a running `hcdn-connector` process.
type child struct {
	cmd         *exec.Cmd
	out, errOut syncBuffer
	done        chan struct{} // closed on exit; code is set then
	code        int
}

var allocConsole sync.Once

// startChild runs `hcdn-connector args...` in a new process group on the test's console.
func startChild(t *testing.T, args ...string) *child {
	t.Helper()
	// GenerateConsoleCtrlEvent reaches only processes on the caller's console.
	// AllocConsole fails when the test has one; without one, the child inherits this one.
	allocConsole.Do(func() { _, _, _ = windows.NewLazySystemDLL("kernel32.dll").NewProc("AllocConsole").Call() })
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c := &child{cmd: exec.Command(exe, args...), done: make(chan struct{})}
	c.cmd.Env = append(os.Environ(), helperEnv+"=1")
	c.cmd.Stdout, c.cmd.Stderr = &c.out, &c.errOut
	c.cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
	if err := c.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = c.cmd.Wait()
		c.code = c.cmd.ProcessState.ExitCode()
		close(c.done)
	}()
	t.Cleanup(func() {
		_ = c.cmd.Process.Kill()
		<-c.done
		if t.Failed() {
			t.Logf("child stderr:\n%s", c.errOut.String())
		}
	})
	return c
}

// ctrlBreak sends Ctrl-Break to the child's process group and returns its exit code.
func (c *child) ctrlBreak(t *testing.T) int {
	t.Helper()
	if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(c.cmd.Process.Pid)); err != nil {
		t.Fatalf("GenerateConsoleCtrlEvent: %v", err)
	}
	select {
	case <-c.done:
		return c.code
	case <-time.After(20 * time.Second):
		t.Fatal("no exit within 20 s of Ctrl-Break")
		return -1
	}
}

// `run` as its own process proxies a request, then drains and exits 0 on Ctrl-Break.
func TestRunStopsOnCtrlBreak(t *testing.T) {
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	defer svc.Close()
	ca := testpki.NewCA(t)
	edge := testedge.New(t, ca, "bnk", false)
	cfg := writeRunConfig(t, ca, edge, "ingress:\n  - hostname: app.example.com\n    service: "+svc.URL+
		"\n  - service: http_status:404\n")
	c := startChild(t, "run", "--config", cfg)
	s := edge.WaitSession(t)
	if s.HelloErr != nil {
		t.Fatalf("hello: %v", s.HelloErr)
	}
	res := s.Get(t, "app.example.com", "/")
	res.Body.Close()
	if res.StatusCode != http.StatusTeapot {
		t.Fatalf("status %d, hcdn-error %q", res.StatusCode, res.Header.Get(proto.HdrError))
	}
	// cmdRun registers its handler before it dials, so Ctrl-Break reaches it.
	if code := c.ctrlBreak(t); code != exitOK {
		t.Fatalf("run exit %d", code)
	}
}

// `quick` as its own process exits 0 on Ctrl-Break while the edge handshake hangs.
func TestQuickStopsOnCtrlBreak(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- c
		}
	}()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, testpki.NewCA(t).PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	c := startChild(t, "quick", "--url", "http://127.0.0.1:1", "--log-level", "error", "--bootstrap", "127.0.0.1",
		"--server-ca-file", caFile, "--ports", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	// The edge never answers the handshake, so Whoami blocks until the event.
	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(10 * time.Second):
		t.Fatal("quick did not dial")
	}
	// cmdQuick registers its handler before it dials, so Ctrl-Break reaches it.
	if code := c.ctrlBreak(t); code != exitOK || c.errOut.String() != "" {
		t.Fatalf("exit %d: %q", code, c.errOut.String())
	}
}
