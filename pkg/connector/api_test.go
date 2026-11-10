package connector_test

import (
	"testing"

	"github.com/hostinger/hcdn-connector/pkg/connector"
)

// Every type that Status holds has a name outside the package.
var (
	_ connector.Selection     = connector.Status{}.Selection
	_ []connector.ProbeRow    = connector.Selection{}.Probes
	_ []connector.PopInfo     = connector.Status{}.Pops
	_ []connector.SessionInfo = connector.PopInfo{}.Sessions
	_ connector.SessionState  = connector.SessionInfo{}.State
	_ []connector.ErrorEntry  = connector.Status{}.LastErrors
)

func TestSessionStates(t *testing.T) {
	for _, s := range []connector.SessionState{
		connector.SessionConnecting, connector.SessionHandshaking, connector.SessionReady,
		connector.SessionDraining, connector.SessionPaused,
	} {
		if s == "" {
			t.Fatal("empty session state")
		}
	}
}
