//lint:file-ignore SA1019 the fake edge drives an h2 client over an existing conn; net/http has no equivalent.

// Package testedge is a fake tunneld for tests: sessions on the direct port,
// the discovery API and, in nginx mode, the 443 Upgrade path.
package testedge

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/hostinger/hcdn-connector/internal/proto"
	"github.com/hostinger/hcdn-connector/internal/testpki"
	"github.com/hostinger/hcdn-connector/pkg/creds"
)

// Pop is one entry of the fake /_hcdn/v1/pops reply.
type Pop struct {
	Code     string `json:"code"`
	Endpoint string `json:"endpoint"`
	Ports    []int  `json:"ports"`
	Region   string `json:"region"`
	Allowed  bool   `json:"allowed"`
}

// Session is one accepted connector session seen from the fake edge.
type Session struct {
	CC        *http2.ClientConn
	Conn      net.Conn
	Transport string
	Hello     *http.Response
	HelloErr  error
}

// Edge mimics tunneld on the direct port (ALPN routing between sessions
// and the discovery API) and, when nginxMode is set, the nginx 443 SNI
// vserver (ALPN http/1.1 only, Upgrade: hcdn-tunnel relay, /_hcdn/v1/ proxy).
// Set the exported knobs before the connector dials.
type Edge struct {
	PopsGen  atomic.Int64
	Pops     []Pop    // nil: one PoP at 127.0.0.1 on Port()
	Pinned   []string // pinned_pops
	HelloHdr map[string]string
	// EdgeFeatures goes out as hcdn-edge-features on every hello ("": none).
	EdgeFeatures string
	RejectAll    bool         // nginx mode: refuse the Upgrade with 403
	NoHello      bool         // never send hello (hello_timeout path)
	Coalesce     bool         // nginx mode: 101 and h2 preface in one Write
	APIStatus    int          // force this status on every API route
	PopsRaw      []byte       // raw /pops body override
	WhoamiRaw    []byte       // raw /whoami body override
	Dials        atomic.Int64 // sessions accepted (before hello)
	// Owner: when OwnerMode is set, quick whoami replies carry
	// owner {mode, issuer}; a whoami with hcdn-owner-ticket also gets the
	// OwnerVerdict answer (nil: ok with client_id "123456").
	OwnerMode    string
	OwnerIssuer  string
	OwnerVerdict func(ticket string) (status, reason, clientID string)

	t         testing.TB
	ln        net.Listener
	ca        *testpki.CA
	cert      tls.Certificate
	pop       string
	nginxMode bool
	sessions  chan *Session
	mu        sync.Mutex
	alpns     [][]string
	helloGate chan struct{}
	quickZone string
	whoamiHdr []http.Header
}

func New(t testing.TB, ca *testpki.CA, pop string, nginxMode bool, names ...string) *Edge {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &Edge{t: t, ln: ln, ca: ca, pop: pop, nginxMode: nginxMode, sessions: make(chan *Session, 16), HelloHdr: map[string]string{}}
	e.PopsGen.Store(41)
	e.cert = ca.IssueServer(t, append([]string{pop + ".tunnel.example", "localhost"}, names...)...)
	go e.acceptLoop(ln)
	t.Cleanup(func() { ln.Close() })
	return e
}

// ListenAlso accepts on another address with the same port (multi-address PoP).
func (e *Edge) ListenAlso(t testing.TB, addr string) bool {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(addr, strconv.Itoa(e.Port())))
	if err != nil {
		return false
	}
	go e.acceptLoop(ln)
	t.Cleanup(func() { ln.Close() })
	return true
}

func (e *Edge) listener() net.Listener {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.ln
}

func (e *Edge) Port() int { return e.listener().Addr().(*net.TCPAddr).Port }

// CloseListener stops accepting; existing sessions stay open.
func (e *Edge) CloseListener() { e.listener().Close() }

// RestartListener mimics a tunneld restart: the port refuses connections for
// gap, then accepts again on the same address. Existing sessions stay open.
// Safe from a goroutine (t.Error only).
func (e *Edge) RestartListener(t testing.TB, gap time.Duration) {
	old := e.listener()
	addr := old.Addr().String()
	old.Close()
	time.Sleep(gap)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Error(err)
		return
	}
	e.mu.Lock()
	e.ln = ln
	e.mu.Unlock()
	go e.acceptLoop(ln)
	t.Cleanup(func() { ln.Close() })
}

func (e *Edge) tlsConfig() *tls.Config {
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{e.cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    e.ca.Pool,
		NextProtos:   []string{proto.ALPNSession, proto.ALPNAPI},
	}
	if e.zone() != "" {
		cfg.ClientAuth = tls.RequireAnyClientCert
		cfg.VerifyPeerCertificate = e.verifyQuickOrCA
	}
	if e.nginxMode {
		cfg.NextProtos = []string{"h2", proto.ALPNHTTP1}
		// nginx: no_application_protocol when the list has neither http/1.1 nor h2.
		cfg.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			e.mu.Lock()
			e.alpns = append(e.alpns, append([]string(nil), chi.SupportedProtos...))
			e.mu.Unlock()
			for _, p := range chi.SupportedProtos {
				if p == proto.ALPNHTTP1 || p == "h2" {
					return nil, nil
				}
			}
			return nil, errors.New("no_application_protocol")
		}
	} else {
		cfg.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			e.mu.Lock()
			e.alpns = append(e.alpns, append([]string(nil), chi.SupportedProtos...))
			e.mu.Unlock()
			return nil, nil
		}
	}
	return cfg
}

// SetQuickZone makes the edge accept self-signed quick leaves (v8 id bound to
// the key) and answer whoami with class quick and <label>.zone.
func (e *Edge) SetQuickZone(zone string) {
	e.mu.Lock()
	e.quickZone = zone
	e.mu.Unlock()
}

func (e *Edge) zone() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.quickZone
}

func quickIDOf(leaf *x509.Certificate) string {
	if id := tunnelIDOf(leaf); creds.IsQuickID(id) {
		return id
	}
	return ""
}

// tunnelIDOf returns the hcdn-tunnel URI SAN of leaf, "" without one.
func tunnelIDOf(leaf *x509.Certificate) string {
	if leaf == nil {
		return ""
	}
	for _, u := range leaf.URIs {
		if u.Scheme == "hcdn-tunnel" {
			return strings.ToLower(u.Opaque)
		}
	}
	return ""
}

func (e *Edge) verifyQuickOrCA(raw [][]byte, _ [][]*x509.Certificate) error {
	leaf, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return err
	}
	if id := quickIDOf(leaf); id != "" {
		if len(raw) != 1 || creds.QuickID(leaf.RawSubjectPublicKeyInfo, leaf.NotBefore) != id {
			return errors.New("quick leaf: bad chain or id")
		}
		return nil
	}
	inter := x509.NewCertPool()
	for _, b := range raw[1:] {
		c, err := x509.ParseCertificate(b)
		if err != nil {
			return err
		}
		inter.AddCert(c)
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: e.ca.Pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return err
}

// SetHelloGate makes every later hello wait for a receive on ch (nil: no wait).
func (e *Edge) SetHelloGate(ch chan struct{}) {
	e.mu.Lock()
	e.helloGate = ch
	e.mu.Unlock()
}

func (e *Edge) OfferedALPNs() [][]string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([][]string(nil), e.alpns...)
}

func (e *Edge) acceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go e.serve(c)
	}
}

func (e *Edge) serve(raw net.Conn) {
	tc := tls.Server(raw, e.tlsConfig())
	if err := tc.Handshake(); err != nil {
		lingeringClose(raw)
		return
	}
	switch tc.ConnectionState().NegotiatedProtocol {
	case proto.ALPNSession:
		e.runSession(tc, proto.TransportDirect)
	case proto.ALPNAPI:
		e.serveAPI(tc, bufio.NewReader(tc))
	case proto.ALPNHTTP1:
		e.serveNginx(tc)
	default:
		tc.Close()
	}
}

// lingeringClose closes raw after a failed handshake the way nginx does: send
// FIN after the alert, then drain until the client closes. Closing with the
// client's bytes still unread makes Windows send RST, which can discard the
// alert before the client reads it.
func lingeringClose(raw net.Conn) {
	if c, ok := raw.(*net.TCPConn); ok {
		_ = c.CloseWrite()
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = io.Copy(io.Discard, c)
	}
	raw.Close()
}

// serveNginx handles the 443 vserver: Upgrade relay or discovery proxy.
func (e *Edge) serveNginx(tc *tls.Conn) {
	br := bufio.NewReader(tc)
	req, err := http.ReadRequest(br)
	if err != nil {
		tc.Close()
		return
	}
	if req.URL.Path == proto.PathConnect {
		if req.Header.Get("Upgrade") != proto.UpgradeToken || req.Header.Get("Connection") != "Upgrade" {
			io.WriteString(tc, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
			tc.Close()
			return
		}
		if e.RejectAll {
			io.WriteString(tc, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
			tc.Close()
			return
		}
		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: hcdn-tunnel\r\nConnection: Upgrade\r\n\r\n"
		if e.Coalesce {
			// 101 + h2 preface in one write: exercises the buffered-bytes (prefixConn) path.
			cc := &coalesceConn{Conn: tc}
			cc.hold([]byte(resp))
			e.runSession(cc, proto.TransportFallback)
			return
		}
		io.WriteString(tc, resp)
		e.runSession(tc, proto.TransportFallback)
		return
	}
	e.handleAPIRequest(tc, req, peerLeaf(tc))
	tc.Close()
}

func peerLeaf(tc *tls.Conn) *x509.Certificate {
	if pc := tc.ConnectionState().PeerCertificates; len(pc) > 0 {
		return pc[0]
	}
	return nil
}

// coalesceConn appends the held bytes in front of the next Write.
type coalesceConn struct {
	net.Conn
	mu      sync.Mutex
	pending []byte
}

func (c *coalesceConn) hold(p []byte) {
	c.mu.Lock()
	c.pending = append([]byte(nil), p...)
	c.mu.Unlock()
}

func (c *coalesceConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending != nil {
		buf := append(c.pending, p...)
		c.pending = nil
		_, err := c.Conn.Write(buf)
		return len(p), err
	}
	return c.Conn.Write(p)
}

func (e *Edge) serveAPI(tc *tls.Conn, br *bufio.Reader) {
	defer tc.Close()
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		e.handleAPIRequest(tc, req, peerLeaf(tc))
	}
}

type popsReply struct {
	Gen        int64    `json:"gen"`
	Pops       []Pop    `json:"pops"`
	PinnedPops []string `json:"pinned_pops"`
}

type whoami struct {
	TunnelID   string       `json:"tunnel_id"`
	CertSerial string       `json:"cert_serial"`
	DaysLeft   int          `json:"days_left"`
	Pop        string       `json:"pop"`
	Node       string       `json:"node"`
	Class      string       `json:"class,omitempty"`
	Hostname   string       `json:"hostname,omitempty"`
	ExpiresAt  *time.Time   `json:"expires_at,omitempty"`
	Owner      *whoamiOwner `json:"owner,omitempty"`
}

type whoamiOwner struct {
	Mode     string `json:"mode"`
	Issuer   string `json:"issuer"`
	Status   string `json:"status,omitempty"`
	Reason   string `json:"reason,omitempty"`
	ClientID string `json:"client_id,omitempty"`
}

// WhoamiHeaders returns the request headers of every whoami so far, in order.
func (e *Edge) WhoamiHeaders() []http.Header {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]http.Header(nil), e.whoamiHdr...)
}

// OwnerTickets returns the hcdn-owner-ticket of every whoami ("" when absent).
func (e *Edge) OwnerTickets() []string {
	var out []string
	for _, h := range e.WhoamiHeaders() {
		out = append(out, h.Get(proto.HdrOwnerTicket))
	}
	return out
}

func (e *Edge) ownerReply(req *http.Request) *whoamiOwner {
	if e.OwnerMode == "" {
		return nil
	}
	o := &whoamiOwner{Mode: e.OwnerMode, Issuer: e.OwnerIssuer}
	if t := req.Header.Get(proto.HdrOwnerTicket); t != "" {
		o.Status, o.Reason, o.ClientID = "ok", "ok", "123456"
		if e.OwnerVerdict != nil {
			o.Status, o.Reason, o.ClientID = e.OwnerVerdict(t)
		}
	}
	return o
}

func (e *Edge) handleAPIRequest(w io.Writer, req *http.Request, peer *x509.Certificate) {
	var body []byte
	status := 200
	switch req.URL.Path {
	case proto.PathPing:
		status = 204
	case proto.PathPops:
		pops := e.Pops
		if pops == nil {
			pops = []Pop{{Code: e.pop, Endpoint: "127.0.0.1", Ports: []int{e.Port()}, Region: "test", Allowed: true}}
		}
		body, _ = json.Marshal(popsReply{Gen: e.PopsGen.Load(), Pops: pops, PinnedPops: e.Pinned})
		if e.PopsRaw != nil {
			body = e.PopsRaw
		}
	case proto.PathWhoami:
		e.mu.Lock()
		e.whoamiHdr = append(e.whoamiHdr, req.Header.Clone())
		e.mu.Unlock()
		wi := whoami{TunnelID: tunnelIDOf(peer), CertSerial: "1", DaysLeft: 100, Pop: e.pop, Node: e.pop + "-edge1"}
		if quickIDOf(peer) != "" {
			id := quickIDOf(peer)
			exp := peer.NotAfter.UTC()
			wi = whoami{TunnelID: id, CertSerial: peer.SerialNumber.Text(16), Pop: e.pop, Node: e.pop + "-edge1",
				Class: "quick", Hostname: creds.QuickHostname(id, e.zone()), ExpiresAt: &exp, Owner: e.ownerReply(req)}
		}
		body, _ = json.Marshal(wi)
		if e.WhoamiRaw != nil {
			body = e.WhoamiRaw
		}
	default:
		status = 404
	}
	if e.APIStatus != 0 {
		status, body = e.APIStatus, nil
	}
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", status, http.StatusText(status), len(body))
	w.Write(body)
}

// runSession acts as tunneld's h2 client: sends hello and hands the conn to the test.
func (e *Edge) runSession(conn net.Conn, transport string) {
	e.Dials.Add(1)
	cc, err := (&http2.Transport{}).NewClientConn(conn)
	if err != nil {
		conn.Close()
		return
	}
	s := &Session{CC: cc, Conn: conn, Transport: transport}
	if e.NoHello {
		e.sessions <- s
		return
	}
	e.mu.Lock()
	gate := e.helloGate
	e.mu.Unlock()
	if gate != nil {
		<-gate
	}
	req, _ := http.NewRequest(http.MethodPost, "https://connector"+proto.PathHello, nil)
	req.Header.Set(proto.HdrProtocol, "1")
	req.Header.Set(proto.HdrEdgeNode, e.pop+"-edge1")
	req.Header.Set(proto.HdrEdgePop, e.pop)
	req.Header.Set(proto.HdrCertDaysLeft, "214")
	req.Header.Set(proto.HdrMaxInflight, "512")
	req.Header.Set(proto.HdrMaxStreams, "128")
	req.Header.Set(proto.HdrPopsGen, strconv.FormatInt(e.PopsGen.Load(), 10))
	if e.EdgeFeatures != "" {
		req.Header.Set(proto.HdrEdgeFeatures, e.EdgeFeatures)
	}
	for k, v := range e.HelloHdr {
		req.Header.Set(k, v)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := cc.RoundTrip(req.WithContext(ctx))
	if err == nil {
		res.Body.Close()
	}
	s.Hello, s.HelloErr = res, err
	e.sessions <- s
}

func (e *Edge) WaitSession(t testing.TB) *Session {
	t.Helper()
	select {
	case s := <-e.sessions:
		return s
	case <-time.After(10 * time.Second):
		t.Fatal("no session within 10 s")
		return nil
	}
}

func (s *Session) Get(t testing.TB, host, path string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "https://"+host+path, nil)
	req.Header.Set(proto.HdrRequestID, "rid-"+path)
	req.Header.Set(proto.HdrVhost, host)
	res, err := s.CC.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func (s *Session) Goaway(t testing.TB, reason string, retryAfter int) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, "https://connector"+proto.PathGoaway, nil)
	req.Header.Set(proto.HdrReason, reason)
	if retryAfter > 0 {
		req.Header.Set(proto.HdrRetryAfter, strconv.Itoa(retryAfter))
	}
	res, err := s.CC.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 204 {
		t.Fatalf("goaway status %d", res.StatusCode)
	}
}

// Visible sends the visible control request with scope and returns the status.
func (s *Session) Visible(t testing.TB, scope string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, "https://connector"+proto.PathVisible, nil)
	req.Header.Set(proto.HdrVisibleScope, scope)
	res, err := s.CC.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

// StaticResolver maps names to fixed addresses (multi-address and dead endpoints).
type StaticResolver map[string][]string

func (r StaticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	addrs, ok := r[host]
	if !ok {
		return nil, errors.New("no such host: " + host)
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, nil
}
