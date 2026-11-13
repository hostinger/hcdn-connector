package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/hostinger/hcdn-connector/internal/testpki"
)

// The install block in docs/standalone.md, run as written by Windows
// PowerShell 5.1, leaves a directory owned by Administrators that `check`
// accepts. %ProgramData% points at a temp directory, and the test binary
// stands in for hcdn-connector.exe on PATH (see TestMain). The block sets
// the owner to Administrators, so it needs an elevated token; GitHub's
// Windows runners have one.
func TestDocsInstallBlock(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token")
	}
	work := t.TempDir()
	programData := filepath.Join(work, "ProgramData")
	src := filepath.Join(work, "src")
	bin := filepath.Join(work, "bin")
	for _, d := range []string{programData, src, bin} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(programData, "hcdn-connector")
	testpki.NewCA(t).WriteCredentials(t, src, tid, []string{"127.0.0.1"}, time.Now().Add(400*24*time.Hour))
	cfg := "tunnel_id: " + tid + "\ncredentials_file: " + filepath.Join(dir, "credentials.json") +
		"\nadmin_socket: \"\"\nmetrics_addr: \"\"\ningress:\n  - service: http_status:404\n"
	if err := os.WriteFile(filepath.Join(src, "config.yml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	installTestBinary(t, filepath.Join(bin, "hcdn-connector.exe"))
	// The BOM makes PowerShell 5.1 read the script as UTF-8. Without an exit
	// line, -File ignores the exit code of the last command.
	script := filepath.Join(work, "install.ps1")
	if err := os.WriteFile(script, []byte("\xef\xbb\xbf"+docsInstallBlock(t)+"\nexit $LASTEXITCODE\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script)
	cmd.Dir = src
	// exec keeps the last of duplicate keys, compared without case on Windows.
	cmd.Env = append(os.Environ(), "ProgramData="+programData, "PATH="+bin+";"+os.Getenv("PATH"), helperEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("install block: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "OK   credentials: ") {
		t.Fatalf("check did not accept the credentials:\n%s", out)
	}
	for _, p := range []string{dir, filepath.Join(dir, "config.yml"), filepath.Join(dir, "credentials.json")} {
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		owner, _, err := sd.Owner()
		if err != nil {
			t.Fatal(err)
		}
		if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			t.Errorf("%s: owner %s, want BUILTIN\\Administrators", p, owner)
		}
	}
}

// docsInstallBlock returns the PowerShell block of docs/standalone.md that creates %ProgramData%\hcdn-connector.
func docsInstallBlock(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "standalone.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.ReplaceAll(string(b), "\r\n", "\n")
	_, rest, ok := strings.Cut(doc, "\n```powershell\n$dir = \"$env:ProgramData\\hcdn-connector\"\n")
	block, _, closed := strings.Cut(rest, "\n```\n")
	if !ok || !closed || !strings.Contains(block, "hcdn-connector.exe check") {
		t.Fatal("docs/standalone.md: no install block that starts with $dir = ... and ends with hcdn-connector.exe check")
	}
	return "$dir = \"$env:ProgramData\\hcdn-connector\"\n" + block
}

// installTestBinary copies the test binary to dst. Not a hard link: a link
// to the running test binary could not be deleted when the test cleans up.
func installTestBinary(t *testing.T, dst string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}
