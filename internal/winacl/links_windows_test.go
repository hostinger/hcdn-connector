//go:build windows

package winacl

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestRemoteDevice(t *testing.T) {
	for _, c := range []struct {
		typ, characteristics uint32
		want                 bool
	}{
		{0x07, 0, false},                       // FILE_DEVICE_DISK: NTFS, ReFS
		{0x07, 0x1, false},                     // removable media
		{0x24, 0, false},                       // FILE_DEVICE_VIRTUAL_DISK
		{0x14, 0x10, true},                     // SMB through the redirector
		{0x14, 0, true},                        // a network file system that does not set FILE_REMOTE_DEVICE
		{0x07, fileRemoteDevice, true},         // any device that says it is remote
		{fileDeviceDfsFileSystem, 0, true},     // DFS
		{fileDeviceNetworkRedirector, 0, true}, // WebDAV
	} {
		if got := remoteDevice(c.typ, c.characteristics); got != c.want {
			t.Errorf("type %#x characteristics %#x: remote %v, want %v", c.typ, c.characteristics, got, c.want)
		}
	}
}

// reparseData builds a REPARSE_DATA_BUFFER whose print name is empty.
func reparseData(tag uint32, target string, flags uint32) []byte {
	name := windows.StringToUTF16(target)
	name = name[:len(name)-1]
	head := 8
	if tag == windows.IO_REPARSE_TAG_SYMLINK {
		head = 12
	}
	b := make([]byte, 8+head+2*len(name))
	binary.LittleEndian.PutUint32(b, tag)
	binary.LittleEndian.PutUint16(b[4:], uint16(len(b)-8))
	binary.LittleEndian.PutUint16(b[10:], uint16(2*len(name))) // substitute name at offset 0
	binary.LittleEndian.PutUint16(b[12:], uint16(2*len(name))) // print name after it, empty
	if tag == windows.IO_REPARSE_TAG_SYMLINK {
		binary.LittleEndian.PutUint32(b[16:], flags)
	}
	for i, c := range name {
		binary.LittleEndian.PutUint16(b[8+head+2*i:], c)
	}
	return b
}

func TestParseReparse(t *testing.T) {
	for _, c := range []struct {
		data     []byte
		target   string
		relative bool
		err      bool
	}{
		{reparseData(windows.IO_REPARSE_TAG_MOUNT_POINT, `\??\C:\Windows`, 0), `C:\Windows`, false, false},
		{reparseData(windows.IO_REPARSE_TAG_MOUNT_POINT, `\??\Volume{0b1e9e4f-0000-0000-0000-100000000000}\`, 0), `\\?\Volume{0b1e9e4f-0000-0000-0000-100000000000}\`, false, false},
		{reparseData(windows.IO_REPARSE_TAG_SYMLINK, `\??\UNC\server\share\dir`, 0), `\\server\share\dir`, false, false},
		{reparseData(windows.IO_REPARSE_TAG_SYMLINK, `..\dir`, symlinkRelative), `..\dir`, true, false},
		{reparseData(windows.IO_REPARSE_TAG_SYMLINK, `\Device\HarddiskVolume2\dir`, 0), "", false, true},
		{reparseData(0x9000001A, `x`, 0), "", false, false}, // a cloud placeholder: no target
		{reparseData(windows.IO_REPARSE_TAG_MOUNT_POINT, `\??\C:\Windows`, 0)[:12], "", false, true},
	} {
		_, target, relative, err := parseReparse(c.data)
		if target != c.target || relative != c.relative || (err != nil) != c.err {
			t.Errorf("got %q relative %v err %v, want %q relative %v err %v", target, relative, err, c.target, c.relative, c.err)
		}
	}
}

// mklink creates a junction; any user can create one where it can create a directory.
func mklink(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v %s", err, out)
	}
}

// setLinkDACL replaces the DACL of the link itself; the path functions follow it.
func setLinkDACL(t *testing.T, link, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(link), windows.WRITE_DAC|windows.READ_CONTROL, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

// longTempDir is t.TempDir with long names: %TEMP% may hold an 8.3 name
// (RUNNER~1), which mklink may expand in the target.
func longTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestOpenTrustedPathLinks(t *testing.T) {
	base := longTempDir(t)
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "config.yml"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	j1, j2 := filepath.Join(base, "j1"), filepath.Join(base, "j2")
	mklink(t, j1, real)
	mklink(t, j2, j1) // a junction to a junction: the target is walked too
	for _, p := range []string{
		filepath.Join(real, "config.yml"),
		filepath.Join(j1, "config.yml"),
		filepath.Join(j2, "config.yml"),
	} {
		f, err := OpenTrustedPath(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		f.Close()
		if want := filepath.Join(real, "config.yml"); f.Name() != want {
			t.Errorf("%s: walked to %s, want %s", p, f.Name(), want)
		}
	}

	// A junction that Users can re-point is refused, also inside the target of another one.
	private, err := PrivateSDDL()
	if err != nil {
		t.Fatal(err)
	}
	setLinkDACL(t, j1, private+"(A;;0x100;;;BU)") // FILE_WRITE_ATTRIBUTES: enough for FSCTL_SET_REPARSE_POINT
	for p, want := range map[string]string{
		filepath.Join(j1, "config.yml"): "link " + j1 + ": grants write access to BUILTIN\\Users",
		filepath.Join(j2, "config.yml"): "through link " + j2 + ": link " + j1 + ": grants write access to BUILTIN\\Users",
	} {
		if f, err := OpenTrustedPath(p); err == nil || !strings.Contains(err.Error(), want) {
			if f != nil {
				f.Close()
			}
			t.Errorf("%s: want %q, got %v", p, want, err)
		}
	}
	setLinkDACL(t, j1, private)
	f, err := OpenTrustedPath(filepath.Join(j2, "config.yml"))
	if err != nil {
		t.Fatalf("DACL restored: %v", err)
	}
	f.Close()

	// A relative symbolic link needs SeCreateSymbolicLinkPrivilege or Developer Mode.
	rel := filepath.Join(base, "rel")
	if err := os.Symlink(`j1\..\real`, rel); err != nil { // not filepath.Join: it drops the ".."
		t.Log("relative symbolic link not checked:", err)
		return
	}
	if f, err = OpenTrustedPath(filepath.Join(rel, "config.yml")); err != nil {
		t.Fatalf("relative symbolic link: %v", err)
	}
	f.Close()
	if want := filepath.Join(real, "config.yml"); f.Name() != want {
		t.Errorf("relative symbolic link: walked to %s, want %s", f.Name(), want)
	}
}

// A network server reports any owner and DACL it likes. The administrative
// share \\localhost\C$ reaches a local directory over SMB.
func TestRemoteRefused(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	vol := filepath.VolumeName(dir)
	unc := `\\localhost\` + vol[:1] + `$` + p[len(vol):]
	f, err := os.Open(unc)
	if err != nil {
		t.Skip("no administrative share:", err)
	}
	defer f.Close()
	if err := CheckTrusted(f); !errors.Is(err, ErrRemote) {
		t.Errorf("CheckTrusted %s: want ErrRemote, got %v", unc, err)
	}
	if g, err := OpenTrustedPath(unc); !errors.Is(err, ErrRemote) {
		if g != nil {
			g.Close()
		}
		t.Errorf("OpenTrustedPath %s: want ErrRemote, got %v", unc, err)
	}

	// A symbolic link to a share (a junction cannot point there) is named.
	link := filepath.Join(t.TempDir(), "share")
	if err := os.Symlink(filepath.Dir(unc), link); err != nil {
		t.Log("symbolic link not checked:", err)
		return
	}
	g, err := OpenTrustedPath(filepath.Join(link, "config.yml"))
	if !errors.Is(err, ErrRemote) || !strings.Contains(err.Error(), "through link "+link+": ") {
		if g != nil {
			g.Close()
		}
		t.Errorf("symbolic link to %s: want ErrRemote through the link, got %v", unc, err)
	}
}
