package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/hostinger/hcdn-connector/internal/termsafe"
	"github.com/hostinger/hcdn-connector/pkg/config"
	"github.com/hostinger/hcdn-connector/pkg/connector"
	"github.com/hostinger/hcdn-connector/pkg/creds"
)

// cmdCheck validates config, credentials and ingress rules, and dials every service.
func cmdCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath, "config file")
	whoami := fs.Bool("whoami", false, "also call GET /_hcdn/v1/whoami on a bootstrap endpoint")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "FAIL config: %v\n", err)
		return exitConfig
	}
	fmt.Fprintf(stdout, "OK   config: %s (tunnel %s, %d ingress rules, ports %v, mode %s)\n",
		*configPath, cfg.TunnelID, len(cfg.Ingress), cfg.Ports, cfg.PopSelection.Mode)
	c, err := connector.New(connector.Options{
		Config: cfg, Version: version, Commit: commit, LogOutput: io.Discard,
		AllowLocalPorts: cfg.AllowLocalPorts,
	})
	if err != nil {
		fmt.Fprintf(stderr, "FAIL %v\n", err)
		return exitConfig
	}
	defer c.Close()
	cur := c.Creds().Current()
	days := int(cur.DaysLeft(time.Now()))
	status := "OK  "
	if days < creds.WarnDaysLeft {
		status = "WARN"
	}
	fmt.Fprintf(stdout, "%s credentials: %s (serial %s, %d days left, bootstrap %v)\n",
		status, cfg.CredentialsFile, cur.Serial, days, cur.BootstrapEndpoints)

	rows, _ := c.Check(context.Background(), connector.CheckOptions{Whoami: *whoami})
	if !printCheckRows(stdout, rows) {
		return exitFailure
	}
	return exitOK
}

// printCheckRows reports whether every row passed. Errors can hold peer
// bytes (origin certificate names, whoami replies), so rows are escaped.
func printCheckRows(w io.Writer, rows []connector.CheckRow) bool {
	ok := true
	for _, r := range rows {
		if r.Kind == connector.CheckWhoami {
			if r.OK {
				fmt.Fprintf(w, "OK   %s %s\n", r.Name, termsafe.String(r.Target))
			} else {
				fmt.Fprintf(w, "FAIL %s: %s\n", r.Name, termsafe.String(r.Err))
			}
		} else if r.OK {
			fmt.Fprintf(w, "OK   %-40s -> %s\n", termsafe.String(r.Name), termsafe.String(r.Target))
		} else {
			fmt.Fprintf(w, "FAIL %-40s -> %s: %s (%s)\n", termsafe.String(r.Name), termsafe.String(r.Target),
				termsafe.String(r.Err), termsafe.String(r.Class))
		}
		ok = ok && r.OK
	}
	return ok
}
