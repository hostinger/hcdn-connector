package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/hostinger/hcdn-connector/internal/admin"
	"github.com/hostinger/hcdn-connector/internal/session"
	"github.com/hostinger/hcdn-connector/internal/termsafe"
	"github.com/hostinger/hcdn-connector/pkg/config"
)

// cmdStatus queries the admin socket and prints the probe and session tables.
func cmdStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath, "config file (to find admin_socket)")
	socket := fs.String("socket", "", "admin socket path (overrides config)")
	asJSON := fs.Bool("json", false, "print the raw JSON")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	path := *socket
	if path == "" {
		path = config.DefaultAdminSocket
		if cfg, err := config.Load(*configPath); err == nil {
			if !cfg.AdminEnabled() {
				fmt.Fprintf(stderr, "status: admin socket disabled in config %s\n", *configPath)
				return exitFailure
			}
			path = cfg.AdminSocket
		} else if _, statErr := os.Stat(*configPath); statErr == nil {
			fmt.Fprintf(stderr, "status: %v\n", err)
			return exitConfig
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var st session.Status
	if err := admin.Fetch(ctx, path, &st); err != nil {
		fmt.Fprintf(stderr, "status: %v\n", err)
		return exitFailure
	}
	if *asJSON {
		if err := printStatusJSON(stdout, st); err != nil {
			fmt.Fprintf(stderr, "status: %v\n", err)
			return exitFailure
		}
		return exitOK
	}
	printStatus(stdout, st)
	return exitOK
}

// printStatusJSON prints st as indented JSON with DEL and C1 escaped, which
// encoding/json leaves raw, so edge-supplied strings cannot drive the terminal.
func printStatusJSON(w io.Writer, st session.Status) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(termsafe.JSON(b), '\n'))
	return err
}

func printStatus(w io.Writer, st session.Status) { printStatusAt(w, st, time.Now()) }

func printStatusAt(w io.Writer, st session.Status, now time.Time) {
	fmt.Fprintf(w, "hcdn-connector %s  connector-id %s  tunnel %s  up %s\n", termsafe.String(st.Version), termsafe.String(st.ConnectorID), termsafe.String(st.TunnelID),
		now.Sub(st.StartedAt).Round(time.Second))
	fmt.Fprintf(w, "certificate serial %s, %d days left\n", termsafe.String(st.CertSerial), st.CertDaysLeft)
	if !st.GlobalPauseUntil.IsZero() {
		fmt.Fprintf(w, "PAUSED (tunnel disabled) until %s\n", st.GlobalPauseUntil.Local().Format(time.RFC3339))
	}
	sel := st.Selection
	fmt.Fprintf(w, "\nselection: %s  (trigger %s at %s, pop list gen %d from %s)\n  reason: %s\n",
		termsafe.String(strings.Join(sel.Pops, ",")), termsafe.String(sel.Trigger), sel.At.Local().Format(time.RFC3339), sel.PopsGen, termsafe.String(sel.Source), termsafe.String(sel.Reason))

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "\nPOP\tENDPOINT\tREGION\tALLOWED\tPINNED\tSELECTED\tPORT\tRTT_MS\tERROR")
	for _, p := range sel.Probes {
		port := "-"
		if p.Port != 0 {
			port = fmt.Sprint(p.Port)
		}
		rtt := "-"
		if p.RTTms > 0 {
			rtt = fmt.Sprintf("%.1f", p.RTTms)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", termsafe.String(p.Pop), termsafe.String(p.Endpoint), termsafe.String(p.Region), yn(p.Allowed), yn(p.Pinned), yn(p.Selected), port, rtt, termsafe.String(p.Error))
	}
	tw.Flush()

	tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "\nPOP\tSLOT\tSTATE\tADDR\tPORT\tTRANSPORT\tEDGE_NODE\tSINCE\tINFLIGHT\tPAUSED_UNTIL")
	for _, p := range st.Pops {
		pop := termsafe.String(p.Pop)
		paused := ""
		if !p.PausedUntil.IsZero() {
			paused = p.PausedUntil.Local().Format(time.RFC3339) + " (" + termsafe.String(p.PauseReason) + ")"
		}
		for _, s := range p.Sessions {
			since := ""
			if !s.Since.IsZero() {
				since = now.Sub(s.Since).Round(time.Second).String()
			}
			state := termsafe.String(string(s.State))
			if state == "" {
				state = "idle"
			}
			inflight := ""
			if s.MaxInflight > 0 {
				inflight = fmt.Sprintf("%d/%d", s.Inflight, s.MaxInflight)
			}
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", pop, s.Slot, state, termsafe.String(s.Addr), orDash(s.Port), termsafe.String(s.Transport), termsafe.String(s.EdgeNode), since, inflight, paused)
		}
		if p.Draining > 0 {
			fmt.Fprintf(tw, "%s\t\tdraining\t%d replaced session(s) finishing streams\t\t\t\t\t\t\n", pop, p.Draining)
		}
		if p.LastError != "" {
			fmt.Fprintf(tw, "%s\t\tlast error\t%s\t\t\t\t%s\t\t\n", pop, termsafe.String(p.LastError), now.Sub(p.LastErrorAt).Round(time.Second).String()+" ago")
		}
	}
	tw.Flush()

	if len(st.LastErrors) > 0 {
		fmt.Fprintln(w, "\nlast errors:")
		for _, e := range st.LastErrors {
			fmt.Fprintf(w, "  %s %-5s %s\n", e.Time.Local().Format("15:04:05"), termsafe.String(e.Level), termsafe.String(e.Message))
		}
	}
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orDash(n int) string {
	if n == 0 {
		return "-"
	}
	return fmt.Sprint(n)
}
