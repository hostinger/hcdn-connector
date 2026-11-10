package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hostinger/hcdn-connector/internal/session"
)

func TestStatusEscapesEdgeControlChars(t *testing.T) {
	const evil = "\x1b[2Jx\x1b]0;pwn\a\u009b"
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	var out bytes.Buffer
	printStatusAt(&out, session.Status{
		Version: evil, ConnectorID: evil, TunnelID: evil, CertSerial: evil, StartedAt: now,
		Selection: session.Selection{Pops: []string{evil}, Reason: evil, Trigger: evil, Source: evil,
			Probes: []session.ProbeRow{{Pop: evil, Endpoint: evil, Region: evil, Error: evil}}},
		Pops: []session.SupervisorInfo{{Pop: evil, PausedUntil: now, PauseReason: evil, Draining: 1,
			LastError: evil, LastErrorAt: now,
			Sessions: []session.SessionInfo{{State: session.State(evil), Addr: evil, Transport: evil, EdgeNode: evil}}}},
		LastErrors: []session.ErrorEntry{{Time: now, Level: evil, Message: evil}},
	}, now)
	s := out.String()
	if strings.ContainsAny(s, "\x1b\a\u009b") {
		t.Fatalf("raw control characters in status output:\n%q", s)
	}
	if !strings.Contains(s, `\x1b[2Jx`) {
		t.Fatalf("escaped region missing from status output:\n%s", s)
	}
}

func TestStatusJSONEscapesEdgeControlChars(t *testing.T) {
	const evil = "\x1b[1m\u009b2J\u009d0;pwn\u009c\x7f"
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	in := session.Status{
		StartedAt: now,
		Selection: session.Selection{Probes: []session.ProbeRow{{Pop: "fra", Error: evil}}},
		Pops: []session.SupervisorInfo{{Pop: "fra", LastError: evil, LastErrorAt: now,
			Sessions: []session.SessionInfo{{EdgeNode: evil}}}},
		LastErrors: []session.ErrorEntry{{Time: now, Level: "WARN", Message: evil}},
	}
	var out bytes.Buffer
	if err := printStatusJSON(&out, in); err != nil {
		t.Fatal(err)
	}
	for _, r := range out.String() {
		if (r < 0x20 && r != '\n') || (r >= 0x7f && r <= 0x9f) {
			t.Fatalf("raw control %U in status --json output:\n%q", r, out.String())
		}
	}
	var back session.Status
	if err := json.Unmarshal(out.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	got := []string{back.Selection.Probes[0].Error, back.Pops[0].LastError, back.Pops[0].Sessions[0].EdgeNode, back.LastErrors[0].Message}
	for _, s := range got {
		if s != evil {
			t.Fatalf("decoded %q, want %q", s, evil)
		}
	}
}
