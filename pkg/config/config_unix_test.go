//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRefusesWorldWritable(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir()) // the error names the real directory
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(p, []byte(valid), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "directory "+dir+": mode 0777 is world-writable") {
		t.Fatalf("config in a world-writable directory must be refused: %v", err)
	}
}
