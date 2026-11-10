package session

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hostinger/hcdn-connector/internal/proto"
)

func TestValidatePopsRejectsNonPrintable(t *testing.T) {
	cases := []struct {
		name string
		pop  string
		ok   bool
	}{
		{"valid", `{"code":"BNK","endpoint":"bnk.tunnel.example","region":"eu north"}`, true},
		{"empty region", `{"code":"bnk","endpoint":"bnk.tunnel.example"}`, true},
		{"esc in region", `{"code":"bnk","endpoint":"bnk.tunnel.example","region":"\u001b[2Jx"}`, false},
		{"bel in code", `{"code":"bn\u0007k","endpoint":"bnk.tunnel.example"}`, false},
		{"c1 in endpoint", `{"code":"bnk","endpoint":"bnk\u009b.tunnel.example"}`, false},
		{"del in region", `{"code":"bnk","endpoint":"bnk.tunnel.example","region":"eu\u007f"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var r PopsReply
			if err := json.Unmarshal([]byte(`{"pops":[`+tc.pop+`]}`), &r); err != nil {
				t.Fatal(err)
			}
			if err := validatePops(&r, []string{"bnk.tunnel.example"}, false); (err == nil) != tc.ok {
				t.Fatalf("validatePops = %v, want ok=%v", err, tc.ok)
			}
		})
	}
	r := PopsReply{Pops: []Pop{{Code: "bnk", Endpoint: "bnk.tunnel.example", Region: "eu\xff"}}}
	if validatePops(&r, []string{"bnk.tunnel.example"}, false) == nil {
		t.Fatal("invalid UTF-8 region must be rejected")
	}
}

func TestValidatePopsEndpointDomain(t *testing.T) {
	named := []string{"fra.tunnel.hostinger.io", "phx.tunnel.hostinger.io"}
	quick := []string{"tunnel.hostinger.io"}
	cases := []struct {
		name      string
		bootstrap []string
		privateCA bool
		endpoint  string
		ok        bool
	}{
		{"sibling of a named bootstrap", named, false, "mum.tunnel.hostinger.io", true},
		{"same as a bootstrap", named, false, "fra.tunnel.hostinger.io", true},
		{"under the quick bootstrap", quick, false, "fra.tunnel.hostinger.io", true},
		{"case and trailing dot", quick, false, "FRA.Tunnel.Hostinger.IO.", true},
		{"staging domain", []string{"tunnel.hostinger.dev"}, false, "bnk.tunnel.hostinger.dev", true},
		{"other domain", quick, false, "fra.tunnel.example.com", false},
		{"lookalike suffix", quick, false, "fra.tunnel.hostinger.io.example.com", false},
		{"lookalike label", quick, false, "fra.tunnelhostinger.io", false},
		{"other tld", quick, false, "fra.tunnel.hostinger.dev", false},
		{"public suffix only", quick, false, "io", false},
		{"ip endpoint", quick, false, "192.0.2.10", false},
		{"ip bootstrap", []string{"192.0.2.10"}, false, "fra.tunnel.hostinger.io", false},
		{"no bootstrap", nil, false, "fra.tunnel.hostinger.io", false},
		{"private CA accepts any", quick, true, "edge1.test.example", true},
		{"private CA, ip bootstrap", []string{"127.0.0.1"}, true, "localhost", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := PopsReply{Pops: []Pop{{Code: "fra", Endpoint: tc.endpoint}}}
			if err := validatePops(&r, tc.bootstrap, tc.privateCA); (err == nil) != tc.ok {
				t.Fatalf("validatePops(%q, %q, %v) = %v, want ok=%v", tc.endpoint, tc.bootstrap, tc.privateCA, err, tc.ok)
			}
		})
	}
}

func TestValidateWhoami(t *testing.T) {
	valid := func() *Whoami {
		return &Whoami{TunnelID: "018f2c3a-7b1e-8c4d-9a2b-3c4d5e6f7a8b", CertSerial: "1F0a", DaysLeft: 214, Pop: "fra",
			Node: "fra-edge1", Class: ClassQuick, Hostname: "018f2c3a7b1e8c4d9a2b3c4d5e6f7a8b.hostingerpreview.com",
			Owner: &WhoamiOwner{Mode: "log", Issuer: "wh-api", Status: "invalid", Reason: "unknown_kid", ClientID: "nh_1"}}
	}
	cases := []struct {
		name string
		edit func(*Whoami)
		ok   bool
	}{
		{"valid quick", func(*Whoami) {}, true},
		{"named, before tunneld 0.3.0", func(w *Whoami) { w.Class, w.Hostname, w.Owner = "", "", nil }, true},
		{"first whoami owner", func(w *Whoami) { w.Owner = &WhoamiOwner{Mode: "require", Issuer: "wh-api"} }, true},
		{"upper case id and hostname", func(w *Whoami) {
			w.TunnelID, w.Hostname = strings.ToUpper(w.TunnelID), strings.ToUpper(w.Hostname)
		}, true},
		{"empty pop and node", func(w *Whoami) { w.Pop, w.Node = "", "" }, true},
		{"tunnel_id not a uuid", func(w *Whoami) { w.TunnelID = "tid" }, false},
		{"tunnel_id empty", func(w *Whoami) { w.TunnelID = "" }, false},
		{"esc in tunnel_id", func(w *Whoami) { w.TunnelID = "\x1b[2J" + w.TunnelID[4:] }, false},
		{"cert_serial empty", func(w *Whoami) { w.CertSerial = "" }, false},
		{"cert_serial not hex", func(w *Whoami) { w.CertSerial = "1f:0a" }, false},
		{"bel in cert_serial", func(w *Whoami) { w.CertSerial = "1f\a" }, false},
		{"esc in pop", func(w *Whoami) { w.Pop = "fr\x1ba" }, false},
		{"esc in node", func(w *Whoami) { w.Node = "\x1b[2Jx" }, false},
		{"c1 in class", func(w *Whoami) { w.Class = "quick\u009b" }, false},
		{"invalid utf-8 node", func(w *Whoami) { w.Node = "fra\xff" }, false},
		{"newline in hostname", func(w *Whoami) { w.Hostname = "a.example\nb" }, false},
		{"hostname with a space", func(w *Whoami) { w.Hostname = "a example.com" }, false},
		{"wildcard hostname", func(w *Whoami) { w.Hostname = "*.example.com" }, false},
		{"esc in owner mode", func(w *Whoami) { w.Owner.Mode = "log\x1b" }, false},
		{"del in owner issuer", func(w *Whoami) { w.Owner.Issuer = "wh\x7f" }, false},
		{"tab in owner status", func(w *Whoami) { w.Owner.Status = "ok\t" }, false},
		{"osc 52 in owner reason", func(w *Whoami) { w.Owner.Reason = "\x1b]52;c;eA==\a" }, false},
		{"esc in owner client_id", func(w *Whoami) { w.Owner.ClientID = "\x1b[1m1" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := valid()
			tc.edit(w)
			if err := validateWhoami(w); (err == nil) != tc.ok {
				t.Fatalf("validateWhoami = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestWhoamiOwnerParse(t *testing.T) {
	cases := []struct {
		name, body, mode string
		want             *WhoamiOwner
	}{
		{"tunneld before 0.5.0", `{"tunnel_id":"x","class":"quick"}`, "", nil},
		{"mode off omitted", `{"class":"quick","owner":null}`, "", nil},
		{"mode off sent anyway", `{"owner":{"mode":"off","issuer":"wh-api"}}`, "", &WhoamiOwner{Mode: "off", Issuer: "wh-api"}},
		{"unknown mode", `{"owner":{"mode":"audit","issuer":"wh-api"}}`, "", &WhoamiOwner{Mode: "audit", Issuer: "wh-api"}},
		{"first whoami, log", `{"owner":{"mode":"log","issuer":"wh-api"}}`, proto.OwnerModeLog,
			&WhoamiOwner{Mode: "log", Issuer: "wh-api"}},
		{"require, upper case", `{"owner":{"mode":"Require","issuer":"wh-api-stage"}}`, proto.OwnerModeRequire,
			&WhoamiOwner{Mode: "Require", Issuer: "wh-api-stage"}},
		{"verdict ok", `{"owner":{"mode":"log","issuer":"wh-api","status":"ok","reason":"ok","client_id":"nh_123456789","new":1}}`,
			proto.OwnerModeLog, &WhoamiOwner{Mode: "log", Issuer: "wh-api", Status: "ok", Reason: "ok", ClientID: "nh_123456789"}},
		{"verdict invalid", `{"owner":{"mode":"require","issuer":"wh-api","status":"invalid","reason":"unknown_kid"}}`,
			proto.OwnerModeRequire, &WhoamiOwner{Mode: "require", Issuer: "wh-api", Status: "invalid", Reason: "unknown_kid"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var w Whoami
			if err := json.Unmarshal([]byte(tc.body), &w); err != nil {
				t.Fatal(err)
			}
			if got := w.OwnerMode(); got != tc.mode {
				t.Fatalf("OwnerMode %q, want %q", got, tc.mode)
			}
			if (w.Owner == nil) != (tc.want == nil) || (w.Owner != nil && *w.Owner != *tc.want) {
				t.Fatalf("owner %+v, want %+v", w.Owner, tc.want)
			}
		})
	}
	var nilW *Whoami
	if nilW.OwnerMode() != "" {
		t.Fatal("a nil reply asks for nothing")
	}
}
