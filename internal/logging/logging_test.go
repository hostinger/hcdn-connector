package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/hostinger/hcdn-connector/internal/session"
	"github.com/hostinger/hcdn-connector/pkg/config"
)

func TestNewEscapesControlChars(t *testing.T) {
	evil := []string{"\xc2\x9b2J", "\x7f", "\x1b[1m", "\x9b", "\u009d0;t\u009c"}
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			var out bytes.Buffer
			l := New(&out, config.Log{Format: format}, session.NewErrorRing(4))
			for _, s := range evil {
				l.With("with", s).WithGroup("g").Warn("msg"+s,
					"str", s, "err", errors.New(s), "list", []string{s, s})
			}
			lines := strings.SplitAfter(out.String(), "\n")
			if lines[len(lines)-1] != "" || len(lines) != len(evil)+1 {
				t.Fatalf("want %d newline-terminated records:\n%q", len(evil), out.String())
			}
			for i, line := range lines[:len(evil)] {
				body := strings.TrimSuffix(line, "\n")
				for j := 0; j < len(body); {
					r, n := utf8.DecodeRuneInString(body[j:])
					if (r == utf8.RuneError && n == 1) || r < 0x20 || (r >= 0x7f && r <= 0x9f) {
						t.Fatalf("raw byte %#x in %s log line:\n%q", body[j], format, line)
					}
					j += n
				}
				if format == "json" {
					var m map[string]any
					if err := json.Unmarshal([]byte(line), &m); err != nil {
						t.Fatalf("decode %q: %v", line, err)
					}
					// slog itself turns invalid UTF-8 into U+FFFD.
					want := strings.ToValidUTF8(evil[i], "\uFFFD")
					if m["msg"] != "msg"+want || m["with"] != want || m["g"].(map[string]any)["str"] != want {
						t.Fatalf("decoded %q, want values %q", line, want)
					}
				}
			}
		})
	}
}
