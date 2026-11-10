//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// notifySignals returns the reload (SIGHUP) and stop (SIGTERM, SIGINT) channels.
func notifySignals() (reload, term chan os.Signal, stop func()) {
	reload = make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	term = make(chan os.Signal, 2)
	signal.Notify(term, syscall.SIGTERM, syscall.SIGINT)
	return reload, term, func() { signal.Stop(reload); signal.Stop(term) }
}
