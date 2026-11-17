package quickview

import (
	"bytes"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/hostinger/hcdn-connector/pkg/connector"
)

var (
	testNow     = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	testExpires = testNow.Add(23*time.Hour + 59*time.Minute + 20*time.Second)
	testURL     = "https://quick-7k2m9x.example.com"
	escapes     = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
)

func plain(s string) string { return escapes.ReplaceAllString(s, "") }

func testView(detected bool) (*View, *bytes.Buffer) {
	var out bytes.Buffer
	v := New(&out, Options{Target: "http://localhost:5173", Detected: detected,
		Now: func() time.Time { return testNow }, Location: time.UTC})
	v.size = func() (int, int) { return 120, 40 }
	v.pal = palette{truecolor: true}
	return v, &out
}

func tunnel(reachable bool) connector.QuickTunnel {
	return connector.QuickTunnel{TunnelID: "t-1", Hostname: strings.TrimPrefix(testURL, "https://"),
		URL: testURL, ExpiresAt: testExpires, Reachable: reachable}
}

// screen is the view as a person sees it, without colours.
func screen(v *View) string {
	var b strings.Builder
	for _, l := range v.lines(testNow) {
		b.WriteString(plain(l.render(120)) + "\n")
	}
	return b.String()
}

func contains(t *testing.T, got string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in:\n%s", w, got)
		}
	}
}

func TestConnecting(t *testing.T) {
	v, _ := testView(true)
	got := screen(v)
	contains(t, got, "✓ Found your server at http://localhost:5173", "Opening a secure tunnel",
		"○ Getting your link ready", "Ctrl+C  to cancel")
	if strings.Contains(got, "Your preview link") {
		t.Errorf("box before the tunnel is ready:\n%s", got)
	}
}

func TestReady(t *testing.T) {
	v, _ := testView(false)
	v.Ready(tunnel(true), "Linked to your Hostinger account")
	contains(t, screen(v), "✓ Sharing http://localhost:5173", "✓ Opened a secure tunnel", "✓ Your link is live",
		"╭─ Your preview link ", "│   "+testURL+"   │", "Expires    in 23h 59m, at 11:59 UTC, 30 Oct",
		"Account    Linked to your Hostinger account", "Anyone with the link", "● Live", "Ctrl+C  to stop sharing")
}

func TestReadyWithoutAccount(t *testing.T) {
	v, _ := testView(false)
	v.Ready(tunnel(true), "")
	if got := screen(v); strings.Contains(got, "Account") {
		t.Errorf("account line without an account:\n%s", got)
	}
}

func TestConnectingThenReachable(t *testing.T) {
	v, _ := testView(false)
	v.Ready(tunnel(false), "")
	if got := screen(v); !strings.Contains(got, "Starting up") || strings.Contains(got, "● Live") {
		t.Errorf("before reachable:\n%s", got)
	}
	v.Reachable()
	if got := screen(v); strings.Contains(got, "Starting up") || !strings.Contains(got, "● Live") {
		t.Errorf("after reachable:\n%s", got)
	}
}

func TestPaused(t *testing.T) {
	v, _ := testView(false)
	v.Paused("Too many quick tunnels from your network. Retrying at 12:05.", testNow.Add(5*time.Minute))
	contains(t, screen(v), "● Too many quick tunnels from your network. Retrying at 12:05.")
	v.pauseTill = testNow // the retry time passed
	if got := screen(v); strings.Contains(got, "Too many") {
		t.Errorf("still paused after the retry time:\n%s", got)
	}
}

func TestEnd(t *testing.T) {
	for _, c := range []struct {
		name  string
		ready bool
		e     Ending
		want  []string
	}{
		{"stopped", true, Stopped, []string{"╭─ Link closed ", "○ Preview ended. The link no longer works.\n\n"}},
		{"expired", true, Expired, []string{"○ Preview expired. The link no longer works."}},
		{"failed before ready", false, Failed, []string{"✕ Opening a secure tunnel", "✕ Preview stopped"}},
		{"stopped before ready", false, Stopped, []string{"○ Opening a secure tunnel", "○ Preview ended."}},
	} {
		t.Run(c.name, func(t *testing.T) {
			v, _ := testView(false)
			if c.ready {
				v.Ready(tunnel(true), "")
			}
			v.End(c.e)
			got := screen(v)
			contains(t, got, c.want...)
			if strings.Contains(got, "Ctrl+C") || strings.Contains(got, "Anyone with the link") {
				t.Errorf("running hints after the end:\n%s", got)
			}
		})
	}
}

func TestRedrawsInPlace(t *testing.T) {
	v, out := testView(false)
	v.Start()
	if !strings.Contains(plain(out.String()), logoArt[0]) {
		t.Errorf("Start without the logo:\n%s", plain(out.String()))
	}
	v.End(Stopped)
	rows := len(v.drawn)
	out.Reset()
	if _, err := v.LogWriter(out).Write([]byte("level=WARN msg=x\n")); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if clear := "\x1b[" + strconv.Itoa(rows) + "A\r\x1b[J"; !strings.HasPrefix(got, clear+"level=WARN msg=x\n") {
		t.Errorf("a log line does not clear the view first: %q", got)
	}
	if !strings.HasSuffix(plain(got), "○ Preview ended. The link no longer works.\n\n") {
		t.Errorf("the view is not drawn again below the log line: %q", plain(got))
	}
}

func TestDrawsOnlyChangedRows(t *testing.T) {
	v, out := testView(false)
	v.Start()
	v.End(Stopped)
	out.Reset()
	v.mu.Lock()
	v.draw()
	v.mu.Unlock()
	if out.Len() != 0 {
		t.Errorf("a draw without changes wrote %q", out)
	}
}

func TestTerminalControlsEscaped(t *testing.T) {
	v, _ := testView(false)
	tun := tunnel(true)
	tun.URL = "https://x.example.com\x1b[2J"
	v.Ready(tun, "")
	if got := screen(v); strings.Contains(got, "\x1b") {
		t.Errorf("an escape from the edge reached the terminal: %q", got)
	}
}

func TestLineRenderCuts(t *testing.T) {
	l := line{sp("abc", ""), sp("défg", "\x1b[1m")}
	if got := l.render(5); got != "abc\x1b[1mdé\x1b[0m" {
		t.Errorf("render(5) = %q", got)
	}
}

func TestLogoNarrow(t *testing.T) {
	var narrow bytes.Buffer
	writeLogo(&narrow, palette{}, 60)
	if got := plain(narrow.String()); strings.Contains(got, "██") || !strings.Contains(got, "H O S T I N G E R") {
		t.Errorf("narrow terminal:\n%s", got)
	}
}

func TestPalette256(t *testing.T) {
	if got := (palette{}).fg(colPurple); got != "\x1b[38;5;99m" {
		t.Errorf("256-colour purple = %q", got)
	}
}

func TestRoughDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		20 * time.Second: "under a minute", 45 * time.Minute: "45m", 2 * time.Hour: "2h",
		23*time.Hour + 59*time.Minute: "23h 59m",
	} {
		if got := roughDuration(d); got != want {
			t.Errorf("roughDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestSupportedNotTerminal(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if Supported(f) || Supported(nil) {
		t.Error("a file is not a terminal")
	}
}

func TestShortURLBox(t *testing.T) {
	v, _ := testView(false)
	tun := tunnel(true)
	tun.URL, tun.Hostname = "https://a.io", "a.io"
	v.Ready(tun, "")
	for _, got := range []string{screen(v), func() string { v.End(Stopped); return screen(v) }()} {
		var widths []int
		for _, l := range strings.Split(got, "\n") {
			if strings.ContainsAny(l, "╭│╰") {
				widths = append(widths, utf8.RuneCountInString(strings.TrimRight(l, " ")))
			}
		}
		if len(widths) != 5 {
			t.Fatalf("want 5 box rows, got %d in:\n%s", len(widths), got)
		}
		for _, w := range widths[1:] {
			if w != widths[0] {
				t.Errorf("box rows differ in width %v in:\n%s", widths, got)
				break
			}
		}
	}
}
