package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/hostinger/hcdn-connector/internal/logging"
	"github.com/hostinger/hcdn-connector/internal/proto"
	"github.com/hostinger/hcdn-connector/internal/termsafe"
	"github.com/hostinger/hcdn-connector/pkg/config"
	"github.com/hostinger/hcdn-connector/pkg/connector"
	"github.com/hostinger/hcdn-connector/pkg/localguard"
)

// Set with -ldflags "-X main.quickTermsURL=... -X main.quickFeedbackURL=...".
// quickBootstrap equals connector.DefaultQuickBootstrap (a test checks it);
// it stays a literal so -X can override it.
var (
	quickBootstrap   = "tunnel.hostinger.io"
	quickTermsURL    = ""
	quickFeedbackURL = ""
)

// quickSignIn is the exit 77 message. The standalone binary has no way to get
// an owner ticket, so it must not send the user to `hostinger login`.
const quickSignIn = "hcdn-connector: this edge serves quick tunnels only for a Hostinger account, " +
	"and hcdn-connector quick cannot link one"

type quickFlags struct {
	url, hostHeader, logLevel   string
	bootstrap, serverCA, portsS string
	bootstrapAddrs              []string
	ports                       []int
}

func parseQuickFlags(args []string, stderr io.Writer) (*quickFlags, bool) {
	f := &quickFlags{}
	fs := flag.NewFlagSet("quick", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&f.url, "url", "", "local service, for example http://localhost:8080 (required)")
	fs.StringVar(&f.hostHeader, "host-header", "", "Host header for the service (dev servers such as Vite refuse unknown hosts)")
	fs.StringVar(&f.logLevel, "log-level", "warn", "debug, info, warn or error")
	// Hidden: staging and tests.
	fs.StringVar(&f.bootstrap, "bootstrap", quickBootstrap, "")
	fs.StringVar(&f.serverCA, "server-ca-file", "", "")
	fs.StringVar(&f.portsS, "ports", strconv.Itoa(proto.PortDirect), "")
	fs.Usage = func() {
		fmt.Fprint(stderr, "Usage: hcdn-connector quick --url http://localhost:8080 [--host-header localhost] [--log-level warn]\n")
	}
	if err := fs.Parse(args); err != nil {
		return nil, false
	}
	if f.url == "" || fs.NArg() != 0 {
		fs.Usage()
		return nil, false
	}
	// The logger is built before any config, so check the level here.
	switch f.logLevel {
	case "debug", "info", "warn", "error":
	default:
		fmt.Fprintf(stderr, "--log-level: %q is not debug, info, warn or error\n", f.logLevel)
		return nil, false
	}
	for _, p := range strings.Split(f.portsS, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 1 || n > 65535 {
			fmt.Fprintf(stderr, "--ports: %q is not a port\n", p)
			return nil, false
		}
		f.ports = append(f.ports, n)
	}
	for _, b := range strings.Split(f.bootstrap, ",") {
		b = strings.TrimSpace(b)
		if b == "" {
			fmt.Fprintf(stderr, "--bootstrap: empty entry in %q\n", f.bootstrap)
			return nil, false
		}
		f.bootstrapAddrs = append(f.bootstrapAddrs, b)
	}
	return f, true
}

// cmdQuick runs an anonymous quick tunnel: no account, no files, a random
// hostname that lives at most 24 h.
func cmdQuick(args []string, stdout, stderr io.Writer) int {
	f, ok := parseQuickFlags(args, stderr)
	if !ok {
		return exitUsage
	}
	// SIGHUP stops too: a closed terminal must not leave the tunnel public.
	hup, term, stopSignals := notifySignals()
	defer stopSignals()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-term:
			cancel()
		case <-hup:
			cancel()
		case <-ctx.Done():
		}
	}()
	// No owner ticket in v1: the run is anonymous (hcdn-owner-absent: unsupported).
	return runQuick(ctx, f, nil, stdout, stderr)
}

// runQuick runs one quick tunnel through connector.RunQuick and prints its
// URL and outcome. owner gets the owner ticket when the edge asks for one;
// nil means no way to get it (unsupported).
func runQuick(ctx context.Context, f *quickFlags, owner connector.OwnerTicketFunc, stdout, stderr io.Writer) int {
	ready := false
	expired, err := connector.RunQuick(ctx, connector.QuickOptions{
		URL: f.url, HostHeader: f.hostHeader, Bootstrap: f.bootstrapAddrs, Ports: f.ports, ServerCAFile: f.serverCA,
		Version: version, Logger: logging.New(stderr, config.Log{Format: "text", Level: f.logLevel}, nil), Owner: owner,
		OnReady: func(q connector.QuickTunnel) {
			ready = true
			printQuickReady(stdout, q, owner != nil)
		},
		OnReachable: func(connector.QuickTunnel) { fmt.Fprintln(stdout, "Your quick tunnel is ready.") },
		OnPause: func(p connector.QuickPause) {
			fmt.Fprintf(stderr, "hcdn-connector: too many quick tunnels from your network; retrying at %s\n",
				p.RetryAt.UTC().Format(time.TimeOnly))
		},
	})
	var qe *connector.QuickError
	var ee *connector.ExitError
	switch {
	case err == nil:
		if expired {
			fmt.Fprintln(stdout, "tunnel expired; run the command again for a new URL")
		}
		return exitOK
	case errors.Is(err, localguard.ErrBlocked):
		// Refused before any edge call: the URL reaches a sensitive local port.
		fmt.Fprintf(stderr, "hcdn-connector: --url %s: %s\n", termsafe.String(f.url), termsafe.String(err.Error()))
		return exitUsage
	case errors.As(err, &ee):
		switch {
		case errors.Is(err, connector.ErrTakenDown):
			fmt.Fprintln(stderr, "hcdn-connector: this tunnel was taken down")
		case errors.Is(err, connector.ErrOwnerRequired):
			fmt.Fprintln(stderr, quickSignIn)
		case errors.Is(err, connector.ErrCertRejected):
			fmt.Fprintln(stderr, "hcdn-connector: the edge no longer accepts this tunnel's certificate; run the command again for a new URL")
		default:
			fmt.Fprintf(stderr, "hcdn-connector: stopped: %s\n", termsafe.String(ee.Error()))
		}
		return ee.Code
	case errors.As(err, &qe) && !ready:
		return quickStartFailed(qe, f.ports, stderr)
	}
	fmt.Fprintf(stderr, "hcdn-connector: %s\n", termsafe.String(err.Error()))
	if !ready {
		return exitConfig // options: credentials, ingress, server CA file
	}
	return exitFailure
}

// quickStartFailed prints why the tunnel did not start. qe.Err can hold
// bytes from the edge (certificate names, HTTP replies), so it is escaped.
func quickStartFailed(qe *connector.QuickError, ports []int, stderr io.Writer) int {
	switch qe.Kind {
	case connector.ErrEdgeUnreachable:
		fmt.Fprintf(stderr, "hcdn-connector: outbound TCP %s is blocked on this network: %s\n", joinPorts(ports), termsafe.String(qe.Err.Error()))
	case connector.ErrQuickNotOffered:
		fmt.Fprintf(stderr, "hcdn-connector: the edge does not offer quick tunnels (%s)\n", termsafe.String(qe.Err.Error()))
	case connector.ErrOwnerRequired:
		msg := quickSignIn
		if qe.Owner.OtherEnvironment {
			msg += "; the owner ticket comes from another environment"
		}
		fmt.Fprintln(stderr, msg)
		return exitNoPerm
	default:
		fmt.Fprintf(stderr, "hcdn-connector: the edge refused the quick tunnel: %s\n", termsafe.String(qe.Err.Error()))
	}
	return exitFailure
}

func printQuickReady(stdout io.Writer, q connector.QuickTunnel, withOwner bool) {
	if q.Reachable {
		fmt.Fprintf(stdout, "Your quick tunnel is ready:\n  %s\n", q.URL)
	} else {
		fmt.Fprintf(stdout, "Your quick tunnel is still connecting; it may answer 530 for a few seconds:\n  %s\n", q.URL)
	}
	line := "Expires " + q.ExpiresAt.UTC().Format("2006-01-02 15:04 MST") + "."
	if quickTermsURL != "" {
		line += " Terms: " + quickTermsURL
	}
	if quickFeedbackURL != "" {
		line += " Feedback: " + quickFeedbackURL
	}
	fmt.Fprintln(stdout, line)
	if withOwner {
		if l := ownerLine(q.Owner); l != "" {
			fmt.Fprintln(stdout, l)
		}
	}
}

// ownerLine says whether the run is linked to an account; "" when the edge
// did not ask.
func ownerLine(l connector.OwnerLink) string {
	switch {
	case l.Mode == "":
		return ""
	case l.Linked():
		return "Linked to your Hostinger account."
	case l.OtherEnvironment:
		return "Not linked to an account (ticket from another environment)."
	case l.Ticket != "" && l.Reason != "":
		return "Not linked to an account (" + termsafe.String(l.Reason) + ")."
	case l.Ticket != "":
		return "Not linked to an account (no verdict from the edge)."
	}
	return "Not linked to an account (" + l.Absent + ")."
}

func joinPorts(ports []int) string {
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, "/")
}
