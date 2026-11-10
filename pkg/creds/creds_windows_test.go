//go:build windows

package creds

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/hostinger/hcdn-connector/internal/testpki"
	"github.com/hostinger/hcdn-connector/internal/winacl"
)

func assertPrivate(t *testing.T, path string) {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := winacl.HasOnly(path, u.User.Sid, system); err != nil || !ok {
		t.Fatalf("key DACL must name the owner and SYSTEM only: ok=%v err=%v", ok, err)
	}
}

func TestWriteCSRWindows(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key.pem")
	if err := WriteCSR(key, filepath.Join(dir, "csr.pem")); err != nil {
		t.Fatal(err)
	}
	assertPrivate(t, key)
	if _, err := Load(key, tid); err != nil && strings.Contains(err.Error(), "accessible by") {
		t.Fatalf("the key file must pass the credentials ACL check: %v", err)
	}
}

func TestCredsPermWindows(t *testing.T) {
	ca := testpki.NewCA(t)
	p := ca.WriteCredentials(t, t.TempDir(), tid, []string{"bnk.tunnel.example"}, time.Now().Add(time.Hour))
	private, err := winacl.PrivateSDDL()
	if err != nil {
		t.Fatal(err)
	}
	if err := winacl.Set(p, private+"(A;;FR;;;BU)"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, tid); err == nil || !strings.Contains(err.Error(), "accessible by Users") || !strings.Contains(err.Error(), "/remove:g *S-1-5-32-545") {
		t.Fatalf("Users read must be refused: %v", err)
	}
	// WRITE_DAC lets Users grant themselves read access.
	if err := winacl.Set(p, private+"(A;;WD;;;BU)"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, tid); err == nil || !strings.Contains(err.Error(), "accessible by Users") {
		t.Fatalf("Users WRITE_DAC must be refused: %v", err)
	}
	if err := winacl.Set(p, private+"(A;;FR;;;IU)"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, tid); err == nil || !strings.Contains(err.Error(), "accessible by INTERACTIVE") {
		t.Fatalf("INTERACTIVE read must be refused: %v", err)
	}
	// FILE_WRITE_DATA only: Everyone can swap in its own certificate and key.
	if err := winacl.Set(p, private+"(A;;0x2;;;WD)"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, tid); err == nil || !strings.Contains(err.Error(), "accessible by Everyone") {
		t.Fatalf("Everyone write must be refused: %v", err)
	}
	if err := winacl.Set(p, private); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, tid); err != nil {
		t.Fatalf("owner-only file: %v", err)
	}
}

// Under %ProgramData% any user can create the directory first and then grant
// itself access to the credentials file placed in it.
func TestCredsDirWindows(t *testing.T) {
	ca := testpki.NewCA(t)
	dir := t.TempDir()
	p := ca.WriteCredentials(t, dir, tid, []string{"bnk.tunnel.example"}, time.Now().Add(time.Hour))
	private, err := winacl.PrivateSDDL()
	if err != nil {
		t.Fatal(err)
	}
	if err := winacl.Set(dir, private+"(A;;WD;;;BU)"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, tid); err == nil || !strings.Contains(err.Error(), "credentials "+p+": directory "+dir+": grants write access to") ||
		!strings.Contains(err.Error(), "Users") {
		t.Fatalf("credentials in a directory whose DACL Users can rewrite must be refused: %v", err)
	}
	if err := winacl.Set(dir, private); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, tid); err != nil {
		t.Fatalf("owner-only directory: %v", err)
	}
}
