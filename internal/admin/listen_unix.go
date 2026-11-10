//go:build !windows

package admin

import (
	"net"
	"os"
	"syscall"
)

func mkdirSocketDir(dir string) error { return os.MkdirAll(dir, 0o750) }

// Create the socket 0660: a Chmod after Listen alone leaves a window with the umask mode.
func listenUnix(path string) (net.Listener, error) {
	old := syscall.Umask(0o117)
	defer syscall.Umask(old)
	return net.Listen("unix", path)
}

func restrictSocket(path string) error { return os.Chmod(path, SocketMode) }
