//go:build !windows

package creds

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hostinger/hcdn-connector/internal/testpki"
)

func assertPrivate(t *testing.T, path string) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %04o", st.Mode().Perm())
	}
}

func TestLoadRefusesGroupWorldReadable(t *testing.T) {
	ca := testpki.NewCA(t)
	p := ca.WriteCredentials(t, t.TempDir(), tid, []string{"bnk.tunnel.example"}, time.Now().Add(400*24*time.Hour))
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p, tid); err == nil || !strings.Contains(err.Error(), "group/world readable") {
			t.Fatalf("mode %04o: expected refusal, got %v", mode, err)
		}
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, tid); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRefusesWorldWritableDir(t *testing.T) {
	ca := testpki.NewCA(t)
	dir := realDir(t)
	p := ca.WriteCredentials(t, dir, tid, []string{"bnk.tunnel.example"}, time.Now().Add(time.Hour))
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, tid); err == nil || !strings.Contains(err.Error(), "credentials "+p+": directory "+dir+": mode 0777 is world-writable") {
		t.Fatalf("credentials in a world-writable directory must be refused: %v", err)
	}
}

// A symlink from a private directory does not hide the directory of the file.
func TestLoadRefusesLinkToWorldWritableDir(t *testing.T) {
	ca := testpki.NewCA(t)
	shared := realDir(t)
	target := ca.WriteCredentials(t, shared, tid, []string{"bnk.tunnel.example"}, time.Now().Add(time.Hour))
	p := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, tid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, tid); err == nil || !strings.Contains(err.Error(), "credentials "+p+": directory "+shared+": mode 0777 is world-writable") {
		t.Fatalf("link to credentials in a world-writable directory must be refused: %v", err)
	}
}

// realDir is t.TempDir with symlinks resolved (/var is one on macOS), as the
// errors name directories.
func realDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadRefusesFIFOWithoutBlocking(t *testing.T) {
	p := filepath.Join(t.TempDir(), "credentials.json")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan error, 1)
	go func() { _, err := Load(p, tid); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("expected refusal, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Load blocked on a FIFO")
	}
}

func TestPollRetriesAfterChmod(t *testing.T) {
	ca := testpki.NewCA(t)
	dir := t.TempDir()
	p := ca.WriteCredentials(t, dir, tid, []string{"bnk.tunnel.example"}, time.Now().Add(2*time.Hour))
	s, err := NewStore(p, tid, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	ca.WriteCredentials(t, dir, tid, []string{"bnk.tunnel.example"}, time.Now().Add(3*time.Hour))
	if err := os.Chtimes(p, time.Now(), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	lastErr := s.pollOnce("")
	if !strings.Contains(lastErr, "group/world readable") || s.Generation() != 0 {
		t.Fatalf("0644 file: lastErr=%q gen=%d", lastErr, s.Generation())
	}
	// chmod keeps the mtime: the next poll must still retry.
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if lastErr = s.pollOnce(lastErr); lastErr != "" || s.Generation() != 1 {
		t.Fatalf("after chmod 0600: lastErr=%q gen=%d", lastErr, s.Generation())
	}
}
