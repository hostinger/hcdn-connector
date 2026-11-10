//go:build windows

package fileguard

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/hostinger/hcdn-connector/internal/winacl"
)

func TestCheckWindows(t *testing.T) {
	private, err := winacl.PrivateSDDL()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(p, []byte("x: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Explicit ACEs only: an inheritable one on the directory would reach the file too.
	cases := []struct {
		file, dir string // ACEs added to PrivateSDDL
		want      string // "": accepted
	}{
		{"", "", ""},
		{"(A;;FR;;;BU)", "(A;;FR;;;BU)", ""}, // read access is allowed
		{"", "(A;CI;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)", ""}, // TrustedInstaller, as under C:\Program Files
		{"(A;;0x2;;;BU)", "", "config.yml: grants write access to BUILTIN\\Users"},
		{"(A;;WD;;;WD)", "", "grants write access to Everyone"},
		{"(A;;SD;;;AU)", "", "grants write access to NT AUTHORITY\\Authenticated Users"},
		{"", "(A;;0x2;;;BU)", "directory " + dir + ": grants write access to BUILTIN\\Users"},      // add a file
		{"", "(A;;0x4;;;BU)", "directory " + dir + ": grants write access to BUILTIN\\Users"},      // add a subdirectory
		{"", "(A;;0x40;;;BU)", "directory " + dir + ": grants write access to BUILTIN\\Users"},     // delete a child
		{"", "(A;OICIIO;GW;;;BU)", "directory " + dir + ": grants write access to BUILTIN\\Users"}, // only the files created later
	}
	for _, c := range cases {
		// The directory first: Set propagates its inheritable ACEs to the file.
		if err := winacl.Set(dir, private+c.dir); err != nil {
			t.Fatal(err)
		}
		if err := winacl.Set(p, private+c.file); err != nil {
			t.Fatal(err)
		}
		_, err := ReadFile(p)
		if c.want == "" && err != nil {
			t.Errorf("file %q dir %q: %v", c.file, c.dir, err)
		}
		if c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "only SYSTEM, Administrators")) {
			t.Errorf("file %q dir %q: want %q, got %v", c.file, c.dir, c.want, err)
		}
	}
}

// A file or directory that another account owns is refused. Setting another
// owner needs SeRestorePrivilege (an elevated administrator, as on CI).
func TestCheckOwnerWindows(t *testing.T) {
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(p, []byte("x: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	enableRestorePrivilege(t)
	if err := setOwner(p, users); err != nil {
		t.Skip("cannot set another owner:", err)
	}
	if err := setOwner(p, u.User.Sid); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ path, want string }{
		{p, "config.yml: owned by BUILTIN\\Users"},
		{dir, "directory " + dir + ": owned by BUILTIN\\Users"},
	} {
		if err := setOwner(c.path, users); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadFile(p); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("want %q, got %v", c.want, err)
		}
		if err := setOwner(c.path, u.User.Sid); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ReadFile(p); err != nil {
		t.Fatalf("owner restored: %v", err)
	}
}

func setOwner(path string, sid *windows.SID) error {
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, sid, nil, nil, nil)
}

// enableRestorePrivilege lets this process set any owner. Without the
// privilege the call still succeeds (ERROR_NOT_ALL_ASSIGNED is not an error).
func enableRestorePrivilege(t *testing.T) {
	t.Helper()
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		t.Fatal(err)
	}
	defer tok.Close()
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeRestorePrivilege"), &luid); err != nil {
		t.Fatal(err)
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	if err := windows.AdjustTokenPrivileges(tok, false, &tp, uint32(unsafe.Sizeof(tp)), nil, nil); err != nil {
		t.Fatal(err)
	}
}

// Any user can create a junction under %ProgramData% and re-point it later,
// so a junction in the path is judged itself, not by its target, and the file
// is judged by the directory that really holds it.
func TestCheckJunctionWindows(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir()) // long names: mklink may expand an 8.3 one
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "config.yml"), []byte("x: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "hcdn-connector")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, real).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v %s", err, out)
	}
	p := filepath.Join(link, "config.yml")
	if _, err := ReadFile(p); err != nil {
		t.Fatalf("a junction that this account owns: %v", err)
	}

	private, err := winacl.PrivateSDDL()
	if err != nil {
		t.Fatal(err)
	}
	private = strings.ReplaceAll(private, ";;FA;", ";OICI;FA;") // the file keeps its inherited ACEs
	if err := winacl.Set(real, private+"(A;;0x2;;;BU)"); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(p); err == nil || !strings.Contains(err.Error(), "directory "+real+": grants write access to BUILTIN\\Users") {
		t.Errorf("the target of the junction must be judged: %v", err)
	}
	if err := winacl.Set(real, private); err != nil {
		t.Fatal(err)
	}

	// A junction that another account owns is refused, even to a directory that Administrators own.
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	enableRestorePrivilege(t)
	if err := setOwner(real, admins); err != nil {
		t.Skip("cannot set another owner:", err)
	}
	if err := setLinkOwner(link, users); err != nil {
		t.Skip("cannot set another owner:", err)
	}
	if _, err := ReadFile(p); err == nil || !strings.Contains(err.Error(), "link "+link+": owned by BUILTIN\\Users; only SYSTEM, Administrators") {
		t.Errorf("a junction that Users own must be refused: %v", err)
	}
	if err := setLinkOwner(link, u.User.Sid); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(p); err != nil {
		t.Fatalf("owner restored: %v", err)
	}
}

// setLinkOwner sets the owner of the link itself; SetNamedSecurityInfo may follow it.
func setLinkOwner(link string, sid *windows.SID) error {
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(link), windows.WRITE_OWNER|windows.READ_CONTROL, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, sid, nil, nil, nil)
}
