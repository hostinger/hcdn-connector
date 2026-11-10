package config

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

const valid = `
tunnel_id: 3f9c2a7e-0b3e-4d0a-9d0a-1c8f5e7b2a11
credentials_file: /etc/hcdn-connector/credentials.json
ingress:
  - hostname: shop.example.com
    service: http://127.0.0.1:8080
  - hostname: "*.example.com"
    service: https://10.0.0.5:8443
    origin_request:
      tls_server_name: app.internal
      response_header_timeout: 30s
  - service: http_status:404
`

func TestParseDefaults(t *testing.T) {
	c, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if c.HomePops != 2 || c.SessionsPerPop != 2 {
		t.Fatalf("defaults: %+v", c)
	}
	if c.PopSelection.Mode != ModeAuto || c.PopSelection.ReprobeInterval != 10*time.Minute ||
		c.PopSelection.SwitchMinGainPct != 20 || c.PopSelection.SwitchMinGainMs != 15 ||
		c.PopSelection.Holddown != 30*time.Minute {
		t.Fatalf("pop_selection defaults: %+v", c.PopSelection)
	}
	if len(c.Ports) != 2 || c.Ports[0] != 7844 || c.Ports[1] != 443 {
		t.Fatalf("ports: %v", c.Ports)
	}
	if c.Ingress[0].OriginRequest.ConnectTimeout != 5*time.Second ||
		c.Ingress[0].OriginRequest.ResponseHeaderTimeout != 45*time.Second ||
		c.Ingress[0].OriginRequest.KeepaliveConnections != 16 {
		t.Fatalf("origin_request defaults: %+v", c.Ingress[0].OriginRequest)
	}
	if c.Ingress[1].OriginRequest.ResponseHeaderTimeout != 30*time.Second {
		t.Fatalf("explicit response_header_timeout lost")
	}
	if !c.MetricsEnabled() || *c.MetricsAddr != DefaultMetricsAddr {
		t.Fatalf("metrics default: %v", c.MetricsAddr)
	}
	if c.AdminSocket != DefaultAdminSocket || c.Log.Format != "json" || c.Log.Level != "info" {
		t.Fatalf("misc defaults: %+v", c)
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	_, err := Parse([]byte(valid + "\nunknown_key: 1\n"))
	if err == nil || !strings.Contains(err.Error(), "unknown_key") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
	_, err = Parse([]byte(strings.Replace(valid, "tls_server_name", "tls_servername", 1)))
	if err == nil {
		t.Fatal("expected nested unknown field error")
	}
}

func TestValidationErrors(t *testing.T) {
	cases := map[string]string{
		"missing catch-all":  strings.Replace(valid, "  - service: http_status:404\n", "", 1),
		"catch-all proxied":  strings.Replace(valid, "http_status:404", "http://127.0.0.1:1", 1),
		"catch-all not last": catchAllFirst,
		"home_pops range":    valid + "home_pops: 4\n",
		"sessions range":     valid + "sessions_per_pop: 5\n",
		"bad uuid":           strings.Replace(valid, "3f9c2a7e-0b3e-4d0a-9d0a-1c8f5e7b2a11", "not-a-uuid", 1),
		"manual needs pops":  valid + "pop_selection:\n  mode: manual\n",
		"auto with pops":     valid + "pop_selection:\n  pops: [bnk]\n",
		"bad mode":           valid + "pop_selection:\n  mode: fastest\n",
		"bad port":           valid + "ports: [0]\n",
		"dup port":           valid + "ports: [7844, 7844]\n",
		"bad scheme":         strings.Replace(valid, "http://127.0.0.1:8080", "ftp://127.0.0.1:8080", 1),
		"tls opts on http":   strings.Replace(valid, "http://127.0.0.1:8080", "http://127.0.0.1:8080\n    origin_request:\n      no_tls_verify: true", 1),
		"bad status":         strings.Replace(valid, "http_status:404", "http_status:99", 1),
		"wildcard mid":       strings.Replace(valid, `"*.example.com"`, `"a.*.example.com"`, 1),
		"metrics not local":  valid + "metrics_addr: 0.0.0.0:9112\n",
		"bad pin":            valid + "server_spki_pins: [\"sha256/abc\"]\n",
		"bad transport":      valid + "transport: quic\n",
		"bad log level":      valid + "log:\n  level: trace\n",
		"dup hostname":       strings.Replace(valid, `"*.example.com"`, "shop.example.com", 1),
		"reprobe too short":  valid + "pop_selection:\n  reprobe_interval: 10s\n",
		"empty":              "",
		"service with query": strings.Replace(valid, "http://127.0.0.1:8080", "http://127.0.0.1:8080/?x=1", 1),
		// Bare integers are nanoseconds in yaml: the floors reject them.
		"bare connect_timeout":  strings.Replace(valid, "tls_server_name: app.internal", "connect_timeout: 5", 1),
		"bare response timeout": strings.Replace(valid, "response_header_timeout: 30s", "response_header_timeout: 45", 1),
		"bare holddown":         valid + "pop_selection:\n  holddown: 30\n",
		// Sub-unit values pass yaml but hit the floors.
		"connect_timeout too low":  strings.Replace(valid, "tls_server_name: app.internal", "connect_timeout: 50ms", 1),
		"response timeout too low": strings.Replace(valid, "response_header_timeout: 30s", "response_header_timeout: 500ms", 1),
		"holddown too low":         valid + "pop_selection:\n  holddown: 500ms\n",
		"status below 200":         strings.Replace(valid, "http_status:404", "http_status:101", 1),
		"port outside 7844/443":    valid + "ports: [8443]\n",
		"custom port without CA":   valid + "ports: [7844, 8443]\n",
		"allow_local_ports zero":   valid + "allow_local_ports: [0]\n",
		"allow_local_ports range":  valid + "allow_local_ports: [65536]\n",
		"allow_local_ports string": valid + "allow_local_ports: [redis]\n",
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

// The only catch-all moved to the front: nothing but the "must be last" check can fail.
var catchAllFirst = strings.Replace(strings.Replace(valid, "  - service: http_status:404\n", "", 1),
	"ingress:\n", "ingress:\n  - service: http_status:404\n", 1)

func TestServiceErrorsHidePassword(t *testing.T) {
	for _, svc := range []string{"http://user:s3cret@127.0.0.1:8080", "http://user:s3cret@127.0.0.1:bad"} {
		_, err := Parse([]byte(strings.Replace(valid, "http://127.0.0.1:8080", svc, 1)))
		if err == nil || strings.Contains(err.Error(), "s3cret") {
			t.Fatalf("%s: want an error without the password, got %v", svc, err)
		}
	}
}

func TestCatchAllMustBeLast(t *testing.T) {
	_, err := Parse([]byte(catchAllFirst))
	if err == nil || !strings.Contains(err.Error(), "must be last") || strings.Contains(err.Error(), "only one") {
		t.Fatalf("want only the must-be-last error, got %v", err)
	}
}

func TestDurationFloorsAndCustomPorts(t *testing.T) {
	src := strings.Replace(valid, "tls_server_name: app.internal", "connect_timeout: 100ms", 1)
	src = strings.Replace(src, "response_header_timeout: 30s", "response_header_timeout: 1s", 1)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("floor values must be accepted: %v", err)
	}
	if c.Ingress[1].OriginRequest.ConnectTimeout != 100*time.Millisecond || c.Ingress[1].OriginRequest.ResponseHeaderTimeout != time.Second {
		t.Fatalf("connect_timeout %v", c.Ingress[1].OriginRequest.ConnectTimeout)
	}
	if _, err := Parse([]byte(valid + "pop_selection:\n  holddown: 0s\n")); err != nil {
		t.Fatalf("holddown 0 must be accepted: %v", err)
	}
	if _, err := Parse([]byte(valid + "ports: [8443]\nserver_ca_file: /tmp/ca.pem\n")); err != nil {
		t.Fatalf("a custom port with server_ca_file must be accepted: %v", err)
	}
	if n, ok := ParseStatusService("http_status:200"); !ok || n != 200 {
		t.Fatal("200 is the lowest allowed http_status")
	}
}

func TestExplicitZeroKeepsItsValue(t *testing.T) {
	src := strings.Replace(valid, "tls_server_name: app.internal", "keepalive_connections: 0", 1) +
		"pop_selection:\n  holddown: 0s\n  switch_min_gain_pct: 0\n  switch_min_gain_ms: 0\n"
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	ps := c.PopSelection
	if ps.Holddown != 0 || ps.SwitchMinGainPct != 0 || ps.SwitchMinGainMs != 0 {
		t.Fatalf("explicit zeros replaced by defaults: %+v", ps)
	}
	if c.Ingress[1].OriginRequest.KeepaliveConnections != 0 || c.Ingress[0].OriginRequest.KeepaliveConnections != 16 {
		t.Fatalf("keepalive: rule0=%d rule1=%d", c.Ingress[0].OriginRequest.KeepaliveConnections, c.Ingress[1].OriginRequest.KeepaliveConnections)
	}
}

func TestManualModeAndDisabledMetrics(t *testing.T) {
	c, err := Parse([]byte(valid + "pop_selection:\n  mode: manual\n  pops: [BNK, fast]\nmetrics_addr: \"\"\nhome_pops: 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.PopSelection.Pops[0] != "bnk" {
		t.Fatalf("pops not lowercased: %v", c.PopSelection.Pops)
	}
	if c.MetricsEnabled() {
		t.Fatal("metrics_addr \"\" must disable metrics")
	}
}

const tid = "3f9c2a7e-0b3e-4d0a-9d0a-1c8f5e7b2a11"

func TestDefaultMatchesParse(t *testing.T) {
	got, err := Parse([]byte("tunnel_id: " + tid + "\ncredentials_file: /c.json\ningress:\n  - service: http_status:404\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := Default()
	want.TunnelID, want.CredentialsFile = tid, "/c.json"
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse:\n%+v\nDefault:\n%+v", got, want)
	}
}

func TestDefaultHasCatchAll(t *testing.T) {
	c := Default()
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "tunnel_id") {
		t.Fatalf("Default without a tunnel ID: %v", err)
	}
	c.TunnelID = strings.ToUpper(tid)
	c.AddRule(NewIngressRule("Shop.Example.com.", "http://127.0.0.1:8080"))
	c.AddRule(NewIngressRule("api.example.com", "http://127.0.0.1:8081"))
	c.PopSelection.Holddown = 0
	c.Normalize()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	hosts := []string{}
	for _, r := range c.Ingress {
		hosts = append(hosts, r.Hostname)
	}
	if strings.Join(hosts, ",") != "shop.example.com,api.example.com," || c.Ingress[0].OriginRequest.KeepaliveConnections != 16 {
		t.Fatalf("AddRule must keep the catch-all last: %q", hosts)
	}
	if c.TunnelID != tid || c.PopSelection.Holddown != 0 {
		t.Fatalf("Normalize: %q, explicit zero holddown: %v", c.TunnelID, c.PopSelection.Holddown)
	}
	empty := &Config{}
	empty.AddRule(NewIngressRule("x.example", "http://127.0.0.1:1"))
	if len(empty.Ingress) != 1 {
		t.Fatal("AddRule without a catch-all appends")
	}
}

func TestValidateWithoutFileKeys(t *testing.T) {
	c := Default()
	c.TunnelID = tid
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate needs no credentials_file: %v", err)
	}
	_, err := Parse([]byte(strings.Replace(valid, "credentials_file: /etc/hcdn-connector/credentials.json\n", "", 1)))
	if err == nil || !strings.Contains(err.Error(), "credentials_file: required") {
		t.Fatalf("Parse must still require credentials_file: %v", err)
	}
	c.Ports = nil
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "ports: at least one port is required") {
		t.Fatalf("Validate must refuse a config without ports: %v", err)
	}
}

func TestAdminSocketDisabled(t *testing.T) {
	c, err := Parse([]byte(valid + "admin_socket: \"\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.AdminEnabled() || c.AdminSocket != "" {
		t.Fatalf("admin_socket \"\" must disable the socket: %q", c.AdminSocket)
	}
	c, err = Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if !c.AdminEnabled() || c.AdminSocket != DefaultAdminSocket {
		t.Fatalf("an absent admin_socket keeps the default: %q", c.AdminSocket)
	}
}

func TestDefaultPaths(t *testing.T) {
	want := map[string][2]string{
		"linux":  {"/etc/hcdn-connector/config.yml", "/run/hcdn-connector/admin.sock"},
		"darwin": {"/usr/local/etc/hcdn-connector/config.yml", "/var/run/hcdn-connector/admin.sock"},
	}
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		want["windows"] = [2]string{filepath.Join(pd, "hcdn-connector", "config.yml"), filepath.Join(pd, "hcdn-connector", "run", "admin.sock")}
	}
	w, ok := want[runtime.GOOS]
	if !ok {
		w = want["linux"]
	}
	if DefaultConfigPath != w[0] || DefaultAdminSocket != w[1] {
		t.Fatalf("%s defaults: %q %q", runtime.GOOS, DefaultConfigPath, DefaultAdminSocket)
	}
}

func TestClone(t *testing.T) {
	mk := func() *Config {
		c := Default()
		c.PopSelection.Pops = []string{"bnk"}
		c.ServerSPKIPins = []string{"pin"}
		c.AllowLocalPorts = []int{9200}
		return c
	}
	a := mk()
	b := a.Clone()
	if !reflect.DeepEqual(a, b) {
		t.Fatal("clone differs")
	}
	b.Ports[0], b.Ingress[0].Hostname, b.PopSelection.Pops[0], b.ServerSPKIPins[0] = 1, "x", "y", "z"
	b.AllowLocalPorts[0] = 1
	*b.MetricsAddr = ""
	b.AddRule(NewIngressRule("shop.example.com", "http://127.0.0.1:1"))
	if !reflect.DeepEqual(a, mk()) {
		t.Fatalf("a change to the clone reached the original: %+v", a)
	}
}

func TestAllowLocalPorts(t *testing.T) {
	c, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if c.AllowLocalPorts != nil {
		t.Fatalf("absent key: %v", c.AllowLocalPorts)
	}
	c, err = Parse([]byte(valid + "allow_local_ports: [9200, 1, 65535]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.AllowLocalPorts, []int{9200, 1, 65535}) {
		t.Fatalf("allow_local_ports: %v", c.AllowLocalPorts)
	}
	_, err = Parse([]byte(valid + "allow_local_ports: [9200, 70000]\n"))
	if err == nil || !strings.Contains(err.Error(), "allow_local_ports: 70000 out of range") {
		t.Fatalf("out of range: %v", err)
	}
}

func TestParseStatusService(t *testing.T) {
	if n, ok := ParseStatusService("http_status:503"); !ok || n != 503 {
		t.Fatal("503")
	}
	if _, ok := ParseStatusService("http://x"); ok {
		t.Fatal("not a status service")
	}
}

func TestDecodePin(t *testing.T) {
	good := "sha256/" + strings.Repeat("A", 43) + "="
	if _, err := DecodePin(good); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePin("sha256/short"); err == nil {
		t.Fatal("short pin accepted")
	}
}
