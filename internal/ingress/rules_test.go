package ingress

import (
	"testing"

	"github.com/hostinger/hcdn-connector/pkg/config"
)

const tid = "3f9c2a7e-0b3e-4d0a-9d0a-1c8f5e7b2a11"

func testTable(t testing.TB) *Table {
	t.Helper()
	tbl, err := Build([]config.IngressRule{
		{Hostname: "shop.example.com", Service: "http_status:201"},
		{Hostname: "*.example.com", Service: "http_status:202"},
		{Hostname: "*.deep.example.com", Service: "http_status:203"},
		{Hostname: "*.example.org", Service: "http_status:204"},
		{Service: "http_status:404"},
	}, tid, nil)
	if err != nil {
		t.Fatal(err)
	}
	return tbl
}

func TestMatchPrecedence(t *testing.T) {
	tbl := testTable(t)
	cases := map[string]int{
		"shop.example.com":         201, // exact beats wildcard
		"SHOP.example.com.":        201, // normalized
		"shop.example.com:443":     201, // port stripped
		"a.example.com":            202,
		"a.b.example.com":          202, // any depth
		"x.deep.example.com":       203, // longest wildcard suffix wins
		"deep.example.com":         202, // "*.deep" needs a label below deep
		"example.com":              404, // wildcard never matches the apex
		"other.example.org":        204,
		"unknown.test":             404,
		"":                         404,
		"[2001:db8::1]:8443":       404,
		"notexample.com":           404, // suffix must start at a label boundary
		"shopexample.com":          404,
		"xexample.com":             404,
		"x.example.comm":           404,
		"shop.example.com.evil.io": 404,
		"shop.example.com.:443":    201,
		"a.example.com:8080":       202,
	}
	for host, want := range cases {
		if got := tbl.Match(host).Service.Status; got != want {
			t.Errorf("%q: got %d want %d", host, got, want)
		}
	}
}

// Hosts an origin could read differently from the normalized form must not reach a named rule.
func TestMatchRejectsAmbiguousHosts(t *testing.T) {
	tbl := testTable(t)
	for _, host := range []string{
		"[shop.example.com]:443",
		"[shop.example.com]",
		"[a.example.com]:443",
		"[1.2.3.4]:443",
		"[fe80::1%25eth0]:443",
		"[::1]x",
		"[::1",
		"shop.example.com:",
		"shop.example.com:https",
		"shop.example.com:443:443",
		"shop.example.com:1234567",
		"shop.example.com:-1",
		"shop.example.com:+443",
		"shop.example.com..",
		".shop.example.com",
		"a..example.com",
		"\u212a.example.com:443", // KELVIN SIGN; strings.ToLower folds it to "k"
		"\u212a.example.com",
		"shop.examplé.com",
		"shop example.com",
		"shop.example.com\x00",
		"2001:db8::1",
	} {
		if got := tbl.Match(host).Service.Status; got != 404 {
			t.Errorf("%q: got %d want catch-all 404", host, got)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"SHOP.example.com.":    "shop.example.com",
		"shop.example.com:443": "shop.example.com",
		"[2001:DB8::1]:8443":   "2001:db8::1",
		"[::1]":                "::1",
		"[shop.example.com]":   "",
		"\u212a.example.com":   "",
		"Shop.Example.COM":     "shop.example.com",
	}
	for in, want := range cases {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzMatch(f *testing.F) {
	tbl := testTable(f)
	for _, s := range []string{"shop.example.com", "a.b.example.com", "*.example.com", "", ".", "..", "[::1]:1", "x:y:z"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, host string) {
		r := tbl.Match(host)
		if r == nil || r.Service == nil {
			t.Fatal("match must always return a rule (catch-all)")
		}
	})
}
