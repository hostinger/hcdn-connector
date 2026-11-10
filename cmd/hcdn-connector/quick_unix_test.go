//go:build !windows

package main

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/hostinger/hcdn-connector/internal/testpki"
)

func TestQuickStopsOnSIGHUP(t *testing.T) {
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
	var out, errOut syncBuffer
	code := make(chan int, 1)
	go func() {
		code <- cmdQuick([]string{"--url", "http://127.0.0.1:1", "--log-level", "error", "--bootstrap", "127.0.0.1",
			"--server-ca-file", caFile, "--ports", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)}, &out, &errOut)
	}()
	// The edge never answers the handshake, so Whoami blocks until the signal.
	select {
	case c := <-accepted:
		defer c.Close()
	case <-time.After(10 * time.Second):
		t.Fatal("quick did not dial")
	}
	// cmdQuick has registered its handler by now, so SIGHUP reaches its channel.
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-code:
		if c != exitOK || errOut.String() != "" {
			t.Fatalf("exit %d: %q", c, errOut.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("quick did not stop on SIGHUP")
	}
}
