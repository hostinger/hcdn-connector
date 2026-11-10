package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/hostinger/hcdn-connector/internal/admin"
	"github.com/hostinger/hcdn-connector/internal/logging"
	"github.com/hostinger/hcdn-connector/pkg/config"
	"github.com/hostinger/hcdn-connector/pkg/connector"
)

// shutdownBudget bounds the drain after SIGTERM; below systemd TimeoutStopSec=25s.
const shutdownBudget = 20 * time.Second

func cmdRun(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath, "config file")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	// Registered first: a SIGHUP (systemctl reload) during startup must not kill the process.
	reload, term, stopSignals := notifySignals()
	defer stopSignals()
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "hcdn-connector: %v\n", err)
		return exitConfig
	}
	log := logging.New(os.Stderr, cfg.Log, nil)
	c, err := connector.New(connector.Options{
		Config: cfg, Reload: reload, Version: version, Commit: commit, Log: log,
		AllowLocalPorts: cfg.AllowLocalPorts,
		// Backstop only: Run returns the ExitError after the drain, so deferred cleanup runs.
		OnExit: func(code int) { time.AfterFunc(shutdownBudget, func() { os.Exit(code) }) },
	})
	if err != nil {
		fmt.Fprintf(stderr, "hcdn-connector: %v\n", err)
		return exitConfig
	}
	defer c.Close()

	if cfg.MetricsEnabled() {
		srv, err := c.Metrics().Serve(*cfg.MetricsAddr)
		if err != nil {
			log.Error("metrics listener failed", "addr", *cfg.MetricsAddr, "err", err)
			return exitFailure
		}
		defer srv.Close()
	}
	if cfg.AdminEnabled() {
		adm := &admin.Server{Path: cfg.AdminSocket, Status: func() any { return c.Status() }}
		if err := adm.Start(); err != nil {
			log.Error("admin socket failed", "path", cfg.AdminSocket, "err", err)
			return exitFailure
		}
		defer adm.Close()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		var sig os.Signal
		select {
		case sig = <-term:
		case <-stop:
			return
		}
		log.Info("signal received; draining sessions", "signal", sig.String())
		cancel()
		select {
		case <-term:
			log.Warn("second signal; exiting now")
			os.Exit(exitFailure)
		case <-time.After(shutdownBudget):
			log.Warn("drain did not finish in time; exiting now", "budget", shutdownBudget.String())
			os.Exit(exitFailure)
		case <-stop:
		}
	}()

	if err := c.Run(ctx); err != nil {
		var ee *connector.ExitError
		if errors.As(err, &ee) {
			return ee.Code
		}
		log.Error("connector stopped", "err", err)
		return exitFailure
	}
	return exitOK
}
