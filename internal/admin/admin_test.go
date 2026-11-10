package admin

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shortDir keeps socket paths short: macOS limits them to 104 bytes.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "hc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestStatusSocket(t *testing.T) {
	p := filepath.Join(shortDir(t), "a.sock")
	s := &Server{Path: p, Status: func() any { return map[string]any{"version": "x", "n": 2} }}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	assertSocketPerms(t, p)
	var out map[string]any
	if err := Fetch(context.Background(), p, &out); err != nil {
		t.Fatal(err)
	}
	if out["version"] != "x" || out["n"].(float64) != 2 {
		t.Fatalf("status %v", out)
	}
	// A second instance must not take over a live socket.
	if err := (&Server{Path: p, Status: func() any { return nil }}).Start(); err == nil {
		t.Fatal("must refuse a socket that another server answers on")
	}
	if err := Fetch(context.Background(), p, &out); err != nil {
		t.Fatalf("the first server must keep its socket: %v", err)
	}
	s.Close()
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (&Server{Path: p, Status: func() any { return nil }}).Start(); err == nil {
		t.Fatal("must refuse a non-socket file at the socket path")
	}
	os.Remove(p)

	// A stale socket (no listener, e.g. after a crash) is replaced on the next start.
	stale, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()
	if st, err := os.Lstat(p); err != nil || st.Mode()&os.ModeSocket == 0 {
		t.Fatalf("stale socket setup: %v", err)
	}
	s2 := &Server{Path: p, Status: func() any { return map[string]any{"n": 3} }}
	if err := s2.Start(); err != nil {
		t.Fatalf("stale socket must be replaced: %v", err)
	}
	if err := Fetch(context.Background(), p, &out); err != nil || out["n"].(float64) != 3 {
		t.Fatalf("fetch from the replacement: %v %v", err, out)
	}
	s2.Close()
	if err := Fetch(context.Background(), p, &out); err == nil {
		t.Fatal("fetch after close must fail")
	}
}

func TestStatusSocketEscapesControlChars(t *testing.T) {
	const evil = "a\x1b[2J\u009b2J\u009d0;t\u009c\x7f"
	p := filepath.Join(shortDir(t), "a.sock")
	s := &Server{Path: p, Status: func() any { return map[string]string{"edge_node": evil} }}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", p)
	}}}
	resp, err := c.Get("http://admin" + StatusPath)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if i := strings.IndexFunc(strings.TrimSuffix(string(body), "\n"), func(r rune) bool {
		return r < 0x20 && r != '\n' || r >= 0x7f && r <= 0x9f
	}); i >= 0 {
		t.Fatalf("raw control at %d in %q", i, body)
	}
	var out map[string]string
	if err := Fetch(context.Background(), p, &out); err != nil {
		t.Fatal(err)
	}
	if out["edge_node"] != evil {
		t.Fatalf("edge_node = %q, want %q", out["edge_node"], evil)
	}
}
