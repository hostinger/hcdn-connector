package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hostinger/hcdn-connector/pkg/config"
	"github.com/hostinger/hcdn-connector/pkg/creds"
)

// cmdCSR generates a P-256 key and a CSR without SANs.
func cmdCSR(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("csr", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "key.pem,csr.pem", "output files: <key>,<csr>")
	tunnelID := fs.String("tunnel-id", "", "tunnel UUID (from hPanel)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	parts := strings.Split(*out, ",")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		fmt.Fprintln(stderr, "csr: --out needs two paths: <key.pem>,<csr.pem>")
		return exitUsage
	}
	if !config.IsUUID(*tunnelID) {
		fmt.Fprintln(stderr, "csr: --tunnel-id must be a UUID")
		return exitUsage
	}
	if err := creds.WriteCSR(parts[0], parts[1]); err != nil {
		fmt.Fprintf(stderr, "csr: %v\n", err)
		return exitFailure
	}
	csr, err := os.ReadFile(parts[1])
	if err != nil {
		fmt.Fprintf(stderr, "csr: %v\n", err)
		return exitFailure
	}
	fmt.Fprintf(stderr, "wrote private key %s (0600) and CSR %s\nSubmit the CSR to POST /v2/tunnels/%s/certificates; the key never leaves this host.\n",
		parts[0], parts[1], *tunnelID)
	_, _ = stdout.Write(csr)
	return exitOK
}
