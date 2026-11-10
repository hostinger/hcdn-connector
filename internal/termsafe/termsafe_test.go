package termsafe

import (
	"encoding/json"
	"testing"
)

func TestString(t *testing.T) {
	cases := map[string]string{
		"eu-north":      "eu-north",
		"zürich":        "zürich",
		"\x1b[2Jx":      `\x1b[2Jx`,
		"a\tb\nc\x07":   `a\x09b\x0ac\x07`,
		"del\x7f":       `del\x7f`,
		"csi\u009b2J":   `csi\x9b2J`,
		"bad\xffbyte":   "bad�byte",
		"\x1b]52;c;x\a": `\x1b]52;c;x\x07`,
	}
	for in, want := range cases {
		if got := String(in); got != want {
			t.Errorf("String(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPrintable(t *testing.T) {
	cases := map[string]bool{
		"":           true,
		"pop1-edge1": true,
		"zürich 41":  true,
		"a\tb":       false,
		"\x1b[2J":    false,
		"del\x7f":    false,
		"\u009b2J":   false,
		"bad\xff":    false,
		"nbsp\u00a0": false,
	}
	for in, want := range cases {
		if got := Printable(in); got != want {
			t.Errorf("Printable(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestJSON(t *testing.T) {
	cases := map[string]string{
		`{"a":"zürich"}`:                `{"a":"zürich"}`,
		"{\"a\":\"x\u009b2J\x7f\"}":     `{"a":"x\u009b2J\u007f"}`,
		"{\"a\":\"\u009d0;t\u009c\"}":   `{"a":"\u009d0;t\u009c"}`,
		"{\"a\":\"lone\x9bbyte\"}":      `{"a":"lone�byte"}`,
		"[\"\u0080\",\"\u009f\",\"é\"]": `["\u0080","\u009f","é"]`,
	}
	for in, want := range cases {
		if got := string(JSON([]byte(in))); got != want {
			t.Errorf("JSON(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestJSONRoundTrip checks the escaped document decodes to the same value.
func TestJSONRoundTrip(t *testing.T) {
	in := map[string]string{"s": "a\u009b2J\x7f\u009d0;x\u009c\x1b[1m"}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	out := JSON(b)
	for _, c := range string(out) {
		if c < 0x20 || (c >= 0x7f && c <= 0x9f) {
			t.Fatalf("raw control %U in %q", c, out)
		}
	}
	var back map[string]string
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if back["s"] != in["s"] {
		t.Fatalf("round trip = %q, want %q", back["s"], in["s"])
	}
}
