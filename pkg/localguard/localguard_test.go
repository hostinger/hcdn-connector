package localguard

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// lanIP stands in for this machine's own LAN address.
var lanIP = netip.MustParseAddr("192.168.77.20")

// fakeResolver answers from a map; other names do not resolve.
type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if ips, ok := f[host]; ok {
		return ips, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func testGuard() *Guard {
	return &Guard{
		Resolver: fakeResolver{
			"localtest.me":        {netip.MustParseAddr("127.0.0.1")},
			"rebind.example.com":  {netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("::1")},
			"db.example.com":      {netip.MustParseAddr("203.0.113.5")},
			"mylaptop.lan":        {lanIP},
			"localhost":           {netip.MustParseAddr("203.0.113.9")}, // ignored: localhost is local by name
			"v6only.example.com":  {netip.MustParseAddr("2001:db8::1")},
			"mapped.example.com":  {netip.MustParseAddr("::ffff:127.0.0.1")},
			"remote6.example.com": {netip.MustParseAddr("2001:db8::2")},
		},
		interfaceAddrs: func() ([]net.Addr, error) {
			return []net.Addr{
				&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
				&net.IPNet{IP: lanIP.AsSlice(), Mask: net.CIDRMask(24, 32)},
				&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
			}, nil
		},
	}
}

func TestCheck(t *testing.T) {
	cases := []struct {
		url     string
		blocked bool
	}{
		// Numeric forms the C resolver reads as loopback or unspecified.
		{"http://127.1:9229", true},
		{"http://0:22", true},
		{"http://0x7f000001:6379", true},
		{"http://2130706433:3306", true},
		{"http://0177.0.0.1:5432", true},
		{"http://127.0.0.1:22", true},
		{"http://127.1.2.3:27017", true},
		{"http://0.0.0.0:2375", true},
		{"http://[::1]:9200", true},
		{"http://[::1%25lo0]:11211", true},
		{"http://[::]:9222", true},
		{"http://[::ffff:127.0.0.1]:6443", true},
		{"http://[::ffff:7f00:1]:6060", true},
		{"http://localhost.:6379", true},
		{"http://LOCALHOST:3306", true},
		{"http://app.localhost:5432", true},
		{"http://host.docker.internal:6379", true},
		{"https://localhost:25", true},
		{"http://:8500", true}, // an empty host dials this machine
		// Names that resolve to this machine.
		{"http://localtest.me:6379", true},
		{"http://rebind.example.com:9229", true}, // any local answer counts
		{"http://mapped.example.com:2380", true},
		{"http://mylaptop.lan:10255", true},
		{"http://192.168.77.20:631", true}, // the machine's own LAN IP
		{"http://[fe80::1%25en0]:5900", true},
		// Allowed ports on this machine.
		{"http://localhost:5173", false},
		{"http://127.1:3000", false},
		{"http://localhost", false},
		{"https://localhost", false},
		{"http://localhost:8888", false}, // Jupyter is warn only
		// Blocked ports elsewhere: they mean nothing here.
		{"http://192.168.1.21:3306", false},
		{"http://db.example.com:5432", false},
		{"http://[2001:db8::1]:22", false},
		{"http://v6only.example.com:6379", false},
		{"http://localhost.example.com:6379", false},
		{"http://unresolvable.example.com:6379", false}, // Control still applies at dial time
	}
	g := testGuard()
	for _, c := range cases {
		err := g.Check(c.url)
		if got := err != nil; got != c.blocked {
			t.Errorf("Check(%s) = %v, want blocked %v", c.url, err, c.blocked)
			continue
		}
		if c.blocked && !errors.Is(err, ErrBlocked) {
			t.Errorf("Check(%s) = %v, want ErrBlocked", c.url, err)
		}
	}
}

func TestCheckMessage(t *testing.T) {
	err := testGuard().Check("http://0:9229")
	var be *BlockedError
	if !errors.As(err, &be) || be.Port.Number != 9229 || be.Port.Service != "the Node inspector" || be.Addr != "0:9229" {
		t.Fatalf("err = %#v", err)
	}
	want := "port 9229 is not shared: it is the usual port of the Node inspector, which must not be reachable from the internet"
	if err.Error() != want {
		t.Fatalf("message %q, want %q", err, want)
	}
}

func TestCheckBadURL(t *testing.T) {
	for _, u := range []string{"http://localhost:99999", "http://[::1", "http://localhost:x"} {
		if err := testGuard().Check(u); err == nil || errors.Is(err, ErrBlocked) {
			t.Errorf("Check(%s) = %v, want a parse error", u, err)
		}
	}
}

func TestMatchWarnOnly(t *testing.T) {
	g := testGuard()
	p, err := g.Match(context.Background(), "http://127.0.0.1:8888")
	if err != nil || p == nil || !p.WarnOnly || p.Service != "Jupyter" {
		t.Fatalf("Match = %+v, %v", p, err)
	}
	if p, _ := g.Match(context.Background(), "http://db.example.com:8888"); p != nil {
		t.Fatalf("a remote 8888 matched: %+v", p)
	}
	if p, _ := g.Match(context.Background(), "http://localhost:5173"); p != nil {
		t.Fatalf("an unlisted port matched: %+v", p)
	}
}

func TestAllow(t *testing.T) {
	g := testGuard()
	g.Allow = []int{8500}
	if err := g.Check("http://127.0.0.1:8500"); err != nil {
		t.Fatalf("allowed port: %v", err)
	}
	if err := g.Control("tcp4", "127.0.0.1:8500", nil); err != nil {
		t.Fatalf("allowed port at dial time: %v", err)
	}
	if err := g.Check("http://127.0.0.1:6379"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("other ports stay blocked: %v", err)
	}
}

func TestControl(t *testing.T) {
	cases := []struct {
		network, addr string
		blocked       bool
	}{
		{"tcp4", "127.0.0.1:9229", true},
		{"tcp4", "127.0.0.53:22", true},
		{"tcp4", "0.0.0.0:6379", true},
		{"tcp6", "[::1]:9222", true},
		{"tcp6", "[::]:6060", true},
		{"tcp6", "[::ffff:127.0.0.1]:3306", true},
		{"tcp4", "192.168.77.20:5432", true}, // the machine's own LAN IP
		{"tcp6", "[fe80::1%en0]:27017", true},
		{"udp4", "127.0.0.1:11211", true},
		{"tcp4", "127.0.0.1:5173", false},
		{"tcp4", "127.0.0.1:8888", false}, // warn only
		{"tcp4", "203.0.113.5:22", false},
		{"tcp6", "[2001:db8::1]:6379", false},
		{"unix", "/var/run/docker.sock", false},
	}
	g := testGuard()
	for _, c := range cases {
		err := g.Control(c.network, c.addr, nil)
		if got := err != nil; got != c.blocked {
			t.Errorf("Control(%s, %s) = %v, want blocked %v", c.network, c.addr, err, c.blocked)
		}
		if c.blocked && !errors.Is(err, ErrBlocked) {
			t.Errorf("Control(%s, %s) = %v, want ErrBlocked", c.network, c.addr, err)
		}
	}
	if err := g.Control("tcp", "not-an-ip:22", nil); err == nil {
		t.Error("an unparsable dial address must fail closed")
	}
}

// The real interfaces: a non-loopback address of this machine is refused.
func TestControlRealInterfaces(t *testing.T) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skip(err)
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.IsLoopback() || n.IP.To4() == nil {
			continue
		}
		addr := net.JoinHostPort(n.IP.String(), "6379")
		if err := (&Guard{}).Control("tcp4", addr, nil); !errors.Is(err, ErrBlocked) {
			t.Fatalf("Control(%s) = %v, want ErrBlocked", addr, err)
		}
		return
	}
	t.Skip("no non-loopback IPv4 interface address")
}

func TestBlockedPorts(t *testing.T) {
	ports := BlockedPorts()
	want := []int{22, 23, 25, 110, 143, 445, 631, 2375, 2376, 2379, 2380, 3306, 4444, 5432, 5555, 5900, 5984,
		6060, 6379, 6443, 8500, 8888, 9200, 9222, 9229, 10250, 10255, 11211, 27017}
	if len(ports) != len(want) {
		t.Fatalf("%d ports, want %d", len(ports), len(want))
	}
	for i, p := range ports {
		if p.Number != want[i] || p.Service == "" {
			t.Errorf("ports[%d] = %+v, want %d with a service name", i, p, want[i])
		}
		if p.WarnOnly != (p.Number == 8888) {
			t.Errorf("port %d WarnOnly = %v", p.Number, p.WarnOnly)
		}
	}
	ports[0].Service = "changed"
	if p, _ := LookupPort(22); p.Service != "SSH" {
		t.Error("BlockedPorts must return a copy")
	}
	if _, ok := LookupPort(5173); ok {
		t.Error("5173 is not listed")
	}
}

func TestParseLooseIPv4(t *testing.T) {
	cases := map[string]string{
		"127.1":          "127.0.0.1",
		"0":              "0.0.0.0",
		"2130706433":     "127.0.0.1",
		"0x7f000001":     "127.0.0.1",
		"0X7F.1":         "127.0.0.1",
		"0177.0.0.1":     "127.0.0.1",
		"127.0.1":        "127.0.0.1",
		"10.1.2.3":       "10.1.2.3",
		"256.1":          "",
		"1.2.3.256":      "",
		"1.2.3.4.5":      "",
		"127..1":         "",
		"08":             "",
		"localhost":      "",
		"4294967296":     "",
		"1.16777216":     "",
		"db.example.com": "",
	}
	for in, want := range cases {
		ip, ok := parseLooseIPv4(in)
		got := ""
		if ok {
			got = ip.String()
		}
		if got != want {
			t.Errorf("parseLooseIPv4(%q) = %q, want %q", in, got, want)
		}
	}
}

// A listing is cached; a failure is not, and refuses the address.
func TestLocalAddrsCached(t *testing.T) {
	calls := 0
	g := testGuard()
	list := g.interfaceAddrs
	g.interfaceAddrs = func() ([]net.Addr, error) { calls++; return list() }
	for range 3 {
		if err := g.Control("tcp4", "203.0.113.5:22", nil); err != nil {
			t.Fatalf("remote host: %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("InterfaceAddrs called %d times, want 1 (cached)", calls)
	}

	calls = 0
	errList := errors.New("no interfaces")
	g = &Guard{interfaceAddrs: func() ([]net.Addr, error) { calls++; return nil, errList }}
	for range 3 {
		if err := g.Control("tcp4", "127.0.0.1:22", nil); !errors.Is(err, ErrBlocked) {
			t.Fatalf("loopback without interfaces: %v", err)
		}
		err := g.Control("tcp4", "192.168.77.20:22", nil)
		if !errors.Is(err, ErrBlocked) || !errors.Is(err, errList) {
			t.Fatalf("interface-like address without interfaces: %v, want ErrBlocked wrapping the listing error", err)
		}
	}
	if calls != 3 {
		t.Fatalf("InterfaceAddrs called %d times, want 3 (a failure is not cached)", calls)
	}
}

// While the interface addresses cannot be read, a listed port is refused on
// every host, with the reason; other ports and allowed ones pass, and the
// guard recovers once the addresses can be read.
func TestUnreadableInterfaces(t *testing.T) {
	g := testGuard()
	list := g.interfaceAddrs
	errList := errors.New("address family not supported by protocol")
	var fail bool
	g.interfaceAddrs = func() ([]net.Addr, error) {
		if fail {
			return nil, errList
		}
		return list()
	}
	g.Allow = []int{6379}
	fail = true

	if err := g.Probe(); !errors.Is(err, errList) {
		t.Fatalf("Probe = %v, want the listing error", err)
	}
	for _, addr := range []string{"192.168.77.20:22", "10.0.0.5:2375", "203.0.113.5:5432", "[2001:db8::1]:10250"} {
		err := g.Control("tcp4", addr, nil)
		var be *BlockedError
		if !errors.As(err, &be) || !errors.Is(err, ErrBlocked) || !errors.Is(err, errList) {
			t.Fatalf("Control(%s) = %v, want a *BlockedError wrapping the listing error", addr, err)
		}
		if msg := err.Error(); !strings.Contains(msg, "cannot be read") || !strings.Contains(msg, "may be this machine") {
			t.Errorf("Control(%s) message %q does not say why", addr, msg)
		}
	}
	for _, addr := range []string{"192.168.77.20:3000", "203.0.113.5:443", "192.168.77.20:6379", "192.168.77.20:8888"} {
		if err := g.Control("tcp4", addr, nil); err != nil {
			t.Errorf("Control(%s) = %v, want nil (not listed, allowed or warn-only)", addr, err)
		}
	}
	err := g.Check("http://db.example.com:5432")
	if !errors.Is(err, ErrBlocked) || !errors.Is(err, errList) {
		t.Errorf("Check(db.example.com:5432) = %v, want ErrBlocked wrapping the listing error", err)
	}
	if err := g.Check("http://db.example.com:3000"); err != nil {
		t.Errorf("Check(db.example.com:3000) = %v, want nil", err)
	}
	if p, err := g.Match(context.Background(), "http://db.example.com:8888"); err != nil || p == nil || p.Number != 8888 {
		t.Errorf("Match(db.example.com:8888) = %v, %v, want the warn-only port", p, err)
	}

	fail = false
	if err := g.Probe(); err != nil {
		t.Fatalf("Probe after recovery = %v", err)
	}
	if err := g.Control("tcp4", "203.0.113.5:5432", nil); err != nil {
		t.Errorf("remote host after recovery: %v", err)
	}
	if err := g.Check("http://db.example.com:5432"); err != nil {
		t.Errorf("Check(db.example.com:5432) after recovery = %v", err)
	}
	var be *BlockedError
	if err := g.Control("tcp4", "192.168.77.20:22", nil); !errors.As(err, &be) || be.Err != nil {
		t.Errorf("own address after recovery = %v, want a plain *BlockedError", err)
	}
}

// A guarded transport refuses a blocked local port that only appears after
// Check: a redirect from an allowed service, and a DNS answer that changes
// between Check and the dial.
func TestDialTimeAfterCheck(t *testing.T) {
	t.Run("redirect", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://127.0.0.1:6379/", http.StatusFound)
		}))
		defer srv.Close()
		g := &Guard{}
		if err := g.Check(srv.URL); err != nil {
			t.Fatalf("Check(%s): %v", srv.URL, err)
		}
		d := &net.Dialer{Control: g.Control}
		c := &http.Client{Transport: &http.Transport{DialContext: d.DialContext}}
		res, err := c.Get(srv.URL)
		if err == nil {
			res.Body.Close()
			t.Fatal("the redirect to 127.0.0.1:6379 was followed")
		}
		if !errors.Is(err, ErrBlocked) {
			t.Fatalf("err = %v, want ErrBlocked", err)
		}
	})

	t.Run("dns change", func(t *testing.T) {
		// The first answer is remote, every later one is loopback.
		dns := &rebindingDNS{first: [4]byte{203, 0, 113, 5}, then: [4]byte{127, 0, 0, 1}}
		r := &net.Resolver{PreferGo: true, Dial: dns.dial}
		g := &Guard{Resolver: r}
		const target = "http://rebind.test.:6379/"
		if err := g.Check(target); err != nil {
			t.Fatalf("Check saw the remote answer, want it to pass: %v", err)
		}
		d := &net.Dialer{Control: g.Control, Resolver: r}
		c := &http.Client{Transport: &http.Transport{DialContext: d.DialContext}}
		res, err := c.Get(target)
		if err == nil {
			res.Body.Close()
			t.Fatal("the dial reached 127.0.0.1:6379")
		}
		if !errors.Is(err, ErrBlocked) {
			t.Fatalf("err = %v, want ErrBlocked", err)
		}
		if dns.aQueries() < 2 {
			t.Fatalf("%d A queries, want Check and the dial to resolve separately", dns.aQueries())
		}
	})
}

// rebindingDNS is a DNS server over an in-memory stream: the first A query
// gets first, later ones get then; AAAA gets no answer.
type rebindingDNS struct {
	first, then [4]byte
	mu          sync.Mutex
	a           int
}

func (d *rebindingDNS) aQueries() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.a
}

func (d *rebindingDNS) dial(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	go d.serve(server)
	return client, nil
}

// serve answers TCP-framed queries (net.Pipe is not a PacketConn).
func (d *rebindingDNS) serve(c net.Conn) {
	defer c.Close()
	for {
		var n uint16
		if err := binary.Read(c, binary.BigEndian, &n); err != nil {
			return
		}
		q := make([]byte, n)
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		var p dnsmessage.Parser
		h, err := p.Start(q)
		if err != nil {
			return
		}
		question, err := p.Question()
		if err != nil {
			return
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true})
		_ = b.StartQuestions()
		_ = b.Question(question)
		_ = b.StartAnswers()
		if question.Type == dnsmessage.TypeA && strings.HasPrefix(question.Name.String(), "rebind.test.") {
			d.mu.Lock()
			ip := d.then
			if d.a == 0 {
				ip = d.first
			}
			d.a++
			d.mu.Unlock()
			_ = b.AResource(dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 0},
				dnsmessage.AResource{A: ip})
		}
		msg, err := b.Finish()
		if err != nil {
			return
		}
		out := binary.BigEndian.AppendUint16(nil, uint16(len(msg)))
		if _, err := c.Write(append(out, msg...)); err != nil {
			return
		}
	}
}
