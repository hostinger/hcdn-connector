//go:build !windows

package fileguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckUnix(t *testing.T) {
	dir := realDir(t)
	p := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(p, []byte("x: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		file, dir os.FileMode
		want      string // "": accepted
	}{
		{0o644, 0o700, ""},
		{0o664, 0o775, ""}, // group write: a user private group (umask 002)
		{0o666, 0o700, "config.yml: mode 0666 is world-writable"},
		{0o644, 0o777, "directory " + dir + ": mode 0777 is world-writable"},
		{0o644, os.ModeSticky | 0o777, ""}, // sticky, and this user owns both
	}
	for _, c := range cases {
		if err := os.Chmod(p, c.file); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, c.dir); err != nil {
			t.Fatal(err)
		}
		_, err := ReadFile(p)
		if c.want == "" && err != nil {
			t.Errorf("file %04o dir %04o: %v", c.file, c.dir, err)
		}
		if c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("file %04o dir %04o: want %q, got %v", c.file, c.dir, c.want, err)
		}
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

// In a sticky world-writable directory another account can create the file
// first. Changing the owner needs root.
func TestCheckStickyOwnerUnix(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown")
	}
	dir := realDir(t)
	if err := os.Chmod(dir, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(p, []byte("x: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(p, 65534, -1); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(p); err == nil || !strings.Contains(err.Error(), "owned by uid 65534 in the world-writable directory") {
		t.Fatalf("file of another account in a sticky directory: %v", err)
	}
	if err := os.Chown(p, 0, -1); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 65534, -1); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(p); err == nil || !strings.Contains(err.Error(), "world-writable and owned by uid 65534") {
		t.Fatalf("sticky directory of another account: %v", err)
	}
}

// A symlink is judged by the directory of the file it leads to, and the link
// itself by the directory it sits in.
func TestCheckSymlinkUnix(t *testing.T) {
	private, shared := realDir(t), realDir(t)
	target := filepath.Join(shared, "config.yml")
	if err := os.WriteFile(target, []byte("x: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(private, "config.yml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(link); err != nil {
		t.Fatalf("link into a private directory: %v", err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(link); err == nil || !strings.Contains(err.Error(), "directory "+shared+": mode 0777 is world-writable") {
		t.Fatalf("link to a file in a world-writable directory: %v", err)
	}
	if err := os.Chmod(shared, 0o700); err != nil {
		t.Fatal(err)
	}

	// The link sits in the world-writable directory, as the last component
	// or as a directory on the way.
	dirLink := filepath.Join(private, "cfg")
	if err := os.Symlink(shared, dirLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(private, 0o777); err != nil {
		t.Fatal(err)
	}
	for p, l := range map[string]string{link: link, filepath.Join(dirLink, "config.yml"): dirLink} {
		want := "symlink " + l + ": directory " + private + ": mode 0777 is world-writable"
		if _, err := ReadFile(p); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want %q, got %v", p, want, err)
		}
	}
	if err := os.Chmod(private, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(link); err != nil {
		t.Fatalf("own link in a sticky directory: %v", err)
	}
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
}

// The layout of a Kubernetes ConfigMap or Secret volume: two hops of relative
// symlinks, all inside the volume directory.
func TestCheckKubernetesVolumeUnix(t *testing.T) {
	vol := realDir(t)
	ts := filepath.Join(vol, "..2026_11_04_10_00_00.123")
	if err := os.Mkdir(ts, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ts, "config.yml"), []byte("x: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(ts), filepath.Join(vol, "..data")); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(vol, "config.yml")
	if err := os.Symlink("..data/config.yml", p); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadFile(p); err != nil || string(b) != "x: 1\n" {
		t.Fatalf("ReadFile: %q %v", b, err)
	}
}

// The walk follows ".." after a symlink from where the link leads, as open
// does, not lexically.
func TestResolveDotDotUnix(t *testing.T) {
	base := realDir(t)
	sub := filepath.Join(base, "real", "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("real", "sub"), filepath.Join(base, "l")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "real", "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(base)
	for _, p := range []string{"l/../f", "./l/../f", base + "/l/../f"} {
		if _, err := ReadFile(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	t.Chdir(sub)
	if _, err := ReadFile("../../l/../f"); err != nil {
		t.Errorf("relative path above the working directory: %v", err)
	}
}

// A path that no longer leads to the opened file is refused rather than
// judged by the wrong file.
func TestCheckChangedUnix(t *testing.T) {
	dir := realDir(t)
	a, b := filepath.Join(dir, "a.yml"), filepath.Join(dir, "b.yml")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(dir, "config.yml")
	if err := os.Symlink(a, link); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(link)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(b, link); err != nil {
		t.Fatal(err)
	}
	if err := Check(link, f); err == nil || !strings.Contains(err.Error(), "changed while checking") {
		t.Fatalf("link repointed after the open: %v", err)
	}
}

// Through a link, the file still needs a trusted owner in a sticky directory,
// and a link planted in a sticky directory by another account is refused.
func TestCheckSymlinkStickyOwnerUnix(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown")
	}
	private, sticky := realDir(t), realDir(t)
	if err := os.Chmod(sticky, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(sticky, "config.yml")
	if err := os.WriteFile(target, []byte("x: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(target, 65534, -1); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(private, "config.yml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(link); err == nil || !strings.Contains(err.Error(), "owned by uid 65534 in the world-writable directory "+sticky) {
		t.Fatalf("link to a file of another account in a sticky directory: %v", err)
	}

	// Open the target directly: Linux fs.protected_symlinks may refuse to
	// follow the planted link, but macOS and a disabled sysctl do not.
	own := filepath.Join(private, "own.yml")
	if err := os.WriteFile(own, []byte("x: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(sticky, "planted.yml")
	if err := os.Symlink(own, planted); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(planted, 65534, -1); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(own)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := Check(planted, f); err == nil || !strings.Contains(err.Error(), "symlink "+planted+": owned by uid 65534 in the world-writable directory "+sticky) {
		t.Fatalf("link of another account in a sticky directory: %v", err)
	}
}

// realDir is t.TempDir with symlinks resolved (/var is one on macOS), as
// Check names directories.
func realDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
