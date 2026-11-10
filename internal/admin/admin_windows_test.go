//go:build windows

package admin

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/hostinger/hcdn-connector/internal/winacl"
)

func assertSocketPerms(*testing.T, string) {}

// socketDirSIDs are the trustees of SocketDirSDDL.
func socketDirSIDs(t *testing.T) []*windows.SID {
	t.Helper()
	var sids []*windows.SID
	for _, k := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid, windows.WinCreatorOwnerRightsSid} {
		sid, err := windows.CreateWellKnownSid(k)
		if err != nil {
			t.Fatal(err)
		}
		sids = append(sids, sid)
	}
	return sids
}

func TestAdminSocketWindows(t *testing.T) {
	dir := filepath.Join(shortDir(t), "run")
	p := filepath.Join(dir, "a.sock")
	s := &Server{Path: p, Status: func() any { return map[string]any{"n": 1} }}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if ok, err := winacl.HasOnly(dir, socketDirSIDs(t)...); err != nil || !ok {
		t.Fatalf("socket directory DACL must be SYSTEM, Administrators and owner only: ok=%v err=%v", ok, err)
	}
	var out map[string]any
	if err := Fetch(context.Background(), p, &out); err != nil || out["n"].(float64) != 1 {
		t.Fatalf("fetch: %v %v", err, out)
	}

	// An existing directory that Users can open, now or through inheritance, is refused, not used.
	private, err := winacl.PrivateSDDL()
	if err != nil {
		t.Fatal(err)
	}
	for _, ace := range []string{"(A;OICI;FR;;;BU)", "(A;OICIIO;FR;;;BU)"} {
		open := filepath.Join(shortDir(t), "open")
		if err := os.Mkdir(open, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := winacl.Set(open, strings.Replace(private, ";;FA;", ";OICI;FA;", -1)+ace); err != nil {
			t.Fatal(err)
		}
		err = (&Server{Path: filepath.Join(open, "a.sock"), Status: func() any { return nil }}).Start()
		if err == nil || !strings.Contains(err.Error(), "grants access to") || !strings.Contains(err.Error(), "Users") {
			t.Fatalf("%s: a socket directory that Users can open must be refused: %v", ace, err)
		}
	}
}

// The default socket directory sits in the default config directory, which
// any user can create first under %ProgramData%.
func TestConfigDirWindows(t *testing.T) {
	conf := filepath.Join(shortDir(t), "hcdn-connector")
	if err := mkdirSocketDirIn(filepath.Join(conf, "run"), true); err != nil {
		t.Fatal(err)
	}
	if ok, err := winacl.HasOnly(conf, socketDirSIDs(t)...); err != nil || !ok {
		t.Fatalf("a new config directory must be SYSTEM, Administrators and owner only: ok=%v err=%v", ok, err)
	}

	// An existing one may stay readable, but another account must not change it.
	// 0x116 is what %ProgramData% passes to Users: add a file or a subdirectory, write attributes.
	private, err := winacl.PrivateSDDL()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		ace string
		ok  bool
	}{{"(A;OICI;FR;;;BU)", true}, {"(A;CI;0x116;;;BU)", false}, {"(A;;0x40;;;BU)", false}} {
		conf := filepath.Join(shortDir(t), "hcdn-connector")
		if err := os.Mkdir(conf, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := winacl.Set(conf, strings.Replace(private, ";;FA;", ";OICI;FA;", -1)+c.ace); err != nil {
			t.Fatal(err)
		}
		err := mkdirSocketDirIn(filepath.Join(conf, "run"), true)
		if c.ok && err != nil {
			t.Errorf("%s: %v", c.ace, err)
		}
		if !c.ok && (err == nil || !strings.Contains(err.Error(), "config directory "+conf+": grants write access to") || !strings.Contains(err.Error(), "Users")) {
			t.Errorf("%s: a config directory that Users can change must be refused: %v", c.ace, err)
		}
	}
}

// Any user can create the config directory as a junction under %ProgramData%
// and re-point it later: one that only this account can change is followed,
// one that Users can change is refused and named.
func TestConfigDirJunctionWindows(t *testing.T) {
	base := shortDir(t)
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o750); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(base, "hcdn-connector")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", conf, real).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v %s", err, out)
	}
	if err := mkdirSocketDirIn(filepath.Join(conf, "run"), true); err != nil {
		t.Fatal(err)
	}

	private, err := winacl.PrivateSDDL()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString(private + "(A;;0x116;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	// The DACL of the junction itself; SetNamedSecurityInfo may follow it.
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(conf), windows.WRITE_DAC|windows.READ_CONTROL, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	windows.CloseHandle(h)
	if err != nil {
		t.Fatal(err)
	}
	err = mkdirSocketDirIn(filepath.Join(conf, "run"), true)
	if err == nil || !strings.Contains(err.Error(), "config directory "+conf+": link "+conf+": grants write access to BUILTIN\\Users") {
		t.Fatalf("a junction that Users can re-point must be refused: %v", err)
	}
}
