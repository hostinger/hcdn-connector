// Package admin serves the local status socket used by `hcdn-connector status`.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/hostinger/hcdn-connector/internal/termsafe"
)

const (
	SocketMode = os.FileMode(0o660)
	StatusPath = "/status"
	HealthPath = "/healthz"
)

// Server listens on a unix socket (mode 0660; on Windows the directory DACL
// limits access) and answers /status as JSON.
type Server struct {
	Path   string
	Status func() any
	ln     net.Listener
	srv    *http.Server
	inode  os.FileInfo // the socket file this server created
}

func (s *Server) Start() error {
	if err := mkdirSocketDir(filepath.Dir(s.Path)); err != nil {
		return err
	}
	if st, err := os.Lstat(s.Path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("admin socket path %s exists and is not a socket", s.Path)
		}
		if c, err := net.DialTimeout("unix", s.Path, time.Second); err == nil {
			c.Close()
			return fmt.Errorf("admin socket %s answers: another hcdn-connector is running", s.Path)
		}
		_ = os.Remove(s.Path)
	}
	ln, err := listenUnix(s.Path)
	if err != nil {
		return err
	}
	// Close removes the path only if it is still this server's socket.
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := restrictSocket(s.Path); err != nil {
		ln.Close()
		_ = os.Remove(s.Path)
		return err
	}
	if s.inode, err = os.Lstat(s.Path); err != nil {
		ln.Close()
		_ = os.Remove(s.Path)
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc(StatusPath, func(w http.ResponseWriter, r *http.Request) {
		b, err := json.MarshalIndent(s.Status(), "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Status holds edge-supplied text; escape DEL and C1 for readers
		// that pipe the socket to a terminal.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(append(termsafe.JSON(b), '\n'))
	})
	mux.HandleFunc(HealthPath, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	s.ln = ln
	s.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = s.srv.Serve(ln) }()
	return nil
}

func (s *Server) Close() {
	if s.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.srv.Shutdown(ctx)
	}
	if st, err := os.Lstat(s.Path); err == nil && s.inode != nil && os.SameFile(st, s.inode) {
		_ = os.Remove(s.Path)
	}
}

// Fetch queries the socket and decodes /status into out.
func Fetch(ctx context.Context, path string, out any) error {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://hcdn-connector"+StatusPath, nil)
	if err != nil {
		return err
	}
	res, err := tr.RoundTrip(req)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("admin socket %s not found: is hcdn-connector running?", path)
		}
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("status endpoint answered %d", res.StatusCode)
	}
	return json.NewDecoder(res.Body).Decode(out)
}
