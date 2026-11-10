// Command hcdn-connector exposes a private service to Hostinger CDN through
// outbound mTLS sessions (hCDN Tunnel).
package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/hostinger/hcdn-connector/pkg/config"
)

// Set with -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
// A build without them (go install) takes version from the build info.
var (
	version = ""
	commit  = ""
	date    = ""
)

func init() {
	if version == "" {
		info, _ := debug.ReadBuildInfo()
		version = buildInfoVersion(info)
	}
}

// buildInfoVersion is the module version without the "v", as release builds
// print it: "0.2.0" for go install ...@v0.2.0, and a pseudo-version for go
// build in a git checkout. Builds with no module version (go test,
// -buildvcs=false) get "devel".
func buildInfoVersion(info *debug.BuildInfo) string {
	if info == nil || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return "devel"
	}
	return strings.TrimPrefix(info.Main.Version, "v")
}

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
	// EX_NOPERM: the edge serves this quick tunnel only for a Hostinger account.
	exitNoPerm = 77
	// EX_CONFIG: bad config or credentials, and revoked tunnels. The unit sets
	// RestartPreventExitStatus=78 so systemd does not restart-loop.
	exitConfig = 78
)

var defaultConfigPath = config.DefaultConfigPath

var usage = fmt.Sprintf(`hcdn-connector -- Hostinger CDN tunnel connector

Usage:
  hcdn-connector quick   --url http://localhost:8080 [--host-header localhost]
  hcdn-connector run     --config %[1]s
  hcdn-connector check   --config %[1]s [--whoami]
  hcdn-connector csr     --out key.pem,csr.pem --tunnel-id <uuid>
  hcdn-connector status  [--config ...] [--socket %[2]s] [--json]
  hcdn-connector version

Exit codes: 0 ok, 1 failure, 2 usage, 77 quick tunnel needs a Hostinger account,
78 bad config/credentials or tunnel revoked.
`, config.DefaultConfigPath, config.DefaultAdminSocket)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "quick":
		return cmdQuick(args[1:], stdout, stderr)
	case "run":
		return cmdRun(args[1:], stderr)
	case "check":
		return cmdCheck(args[1:], stdout, stderr)
	case "csr":
		return cmdCSR(args[1:], stdout, stderr)
	case "status":
		return cmdStatus(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprint(stdout, versionString())
		return exitOK
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return exitOK
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return exitUsage
}

func versionString() string {
	c, d := commit, date
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && c == "" {
				c = s.Value
			}
			if s.Key == "vcs.time" && d == "" {
				d = s.Value
			}
		}
	}
	if c == "" {
		c = "unknown"
	}
	if d == "" {
		d = "unknown"
	}
	return fmt.Sprintf("hcdn-connector %s\ncommit: %s\nbuilt:  %s\ngo:     %s %s/%s\n",
		version, c, d, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
