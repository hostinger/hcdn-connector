package fileguard

import (
	"os"
	"path/filepath"
	"testing"
)

// A file in a fresh temp directory is what every other package test writes.
func TestReadFileTempDir(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(p, []byte("x: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := ReadFile(p)
	if err != nil || string(b) != "x: 1\n" {
		t.Fatalf("ReadFile: %q %v", b, err)
	}
	if _, err := ReadFile(filepath.Join(t.TempDir(), "none.yml")); !os.IsNotExist(err) {
		t.Fatalf("missing file: %v", err)
	}
}
