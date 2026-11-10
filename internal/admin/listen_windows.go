//go:build windows

package admin

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/hostinger/hcdn-connector/internal/winacl"
	"github.com/hostinger/hcdn-connector/pkg/config"
)

// SocketDirSDDL: SYSTEM, Administrators and the owner; the socket inherits it.
// The default config directory gets it too when the connector creates it.
const SocketDirSDDL = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GA;;;OW)"

// An existing directory keeps its DACL and owner, so both are checked: under
// %ProgramData% any user can create the directory first. That holds for the
// default config directory around run\ as well, which may stay readable but
// must not let another account change it.
func mkdirSocketDir(dir string) error {
	return mkdirSocketDirIn(dir, dir == filepath.Dir(config.DefaultAdminSocket))
}

func mkdirSocketDirIn(dir string, inConfigDir bool) error {
	if inConfigDir {
		if err := mkdirChecked(filepath.Dir(dir), "config directory", "change", winacl.CheckTrusted); err != nil {
			return err
		}
	}
	return mkdirChecked(dir, "admin socket directory", "open", winacl.CheckPrivateDir)
}

func mkdirChecked(dir, what, can string, check func(*os.File) error) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o750); err != nil {
		return err
	}
	if err := winacl.MkdirProtected(dir, SocketDirSDDL); err != nil {
		return err
	}
	// Not os.Open: the directory may be a junction that another account owns and re-points.
	f, err := winacl.OpenTrustedPath(dir)
	if err == nil {
		defer f.Close()
		err = check(f)
	}
	if err != nil {
		return fmt.Errorf("%s %s: %w; remove it so hcdn-connector creates it, or use a directory that only SYSTEM, Administrators and this account own and can %s",
			what, dir, err, can)
	}
	return nil
}

func listenUnix(path string) (net.Listener, error) { return net.Listen("unix", path) }

// Windows ignores the mode bits of an AF_UNIX socket; the directory DACL applies.
func restrictSocket(string) error { return nil }
