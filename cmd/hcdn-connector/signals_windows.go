package main

import (
	"os"
	"os/signal"
	"syscall"
)

// notifySignals: Windows has no SIGHUP, so reload is nil and the 10 s mtime poll applies.
// os.Interrupt is Ctrl-C and Ctrl-Break; Go maps console close, logoff and shutdown to SIGTERM.
func notifySignals() (reload, term chan os.Signal, stop func()) {
	term = make(chan os.Signal, 2)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)
	return nil, term, func() { signal.Stop(term) }
}
