//go:build !windows

package admin

import (
	"os"
	"testing"
)

func assertSocketPerms(t *testing.T, p string) {
	t.Helper()
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != SocketMode {
		t.Fatalf("socket mode %04o", st.Mode().Perm())
	}
}
