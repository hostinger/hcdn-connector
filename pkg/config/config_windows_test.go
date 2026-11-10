//go:build windows

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hostinger/hcdn-connector/internal/winacl"
)

func TestLoadRefusesWritableByUsers(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(p, []byte(valid), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != nil {
		t.Fatal(err)
	}
	private, err := winacl.PrivateSDDL()
	if err != nil {
		t.Fatal(err)
	}
	// Add a file: Users could create credentials.json before the operator does.
	// OICI: Set propagates the DACL, and config.yml must stay readable.
	if err := winacl.Set(dir, strings.Replace(private, ";;FA;", ";OICI;FA;", -1)+"(A;;0x2;;;BU)"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "directory "+dir+": grants write access to") || !strings.Contains(err.Error(), "Users") {
		t.Fatalf("config in a directory that Users can change must be refused: %v", err)
	}
}
