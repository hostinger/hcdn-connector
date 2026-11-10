//lint:file-ignore SA1019 the fake edge drives an h2 client over an existing conn; net/http has no equivalent.

package h2srv

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/hostinger/hcdn-connector/internal/ingress"
	"github.com/hostinger/hcdn-connector/internal/proto"
	"github.com/hostinger/hcdn-connector/pkg/config"
)

const tid = "3f9c2a7e-0b3e-4d0a-9d0a-1c8f5e7b2a11"

// pair returns two ends of a TCP connection: the connector side and the edge side.
func pair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var srv net.Conn
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv, _ = ln.Accept()
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	return srv, cli
}

func edgeClient(t *testing.T, c net.Conn) *http2.ClientConn {
	t.Helper()
	cc, err := (&http2.Transport{}).NewClientConn(c)
	if err != nil {
		t.Fatal(err)
	}
	return cc
}

func table(t *testing.T, service string) *ingress.Table {
	t.Helper()
	tbl, err := ingress.Build([]config.IngressRule{
		{Hostname: "shop.example.com", Service: service, OriginRequest: originDefaults()},
		{Service: "http_status:404"},
	}, tid, nil)
	if err != nil {
		t.Fatal(err)
	}
	return tbl
}

func originDefaults() config.OriginRequest {
	return config.OriginRequest{ConnectTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second, KeepaliveConnections: 4}
}

type events struct {
	mu      sync.Mutex
	hello   []Hello
	goaway  []Goaway
	visible []Visible
}

func start(t *testing.T, tbl *ingress.Table, ev *events, helloTimeout time.Duration) (*Session, *http2.ClientConn, chan error) {
	t.Helper()
	return startOpts(t, tbl, ev, helloTimeout, nil)
}

func startOpts(t *testing.T, tbl *ingress.Table, ev *events, helloTimeout time.Duration, edit func(*Options)) (*Session, *http2.ClientConn, chan error) {
	t.Helper()
	srvConn, cliConn := pair(t)
	h := ingress.NewHandler(tbl, tid, slog.Default(), nil)
	o := Options{
		Handler: h, Version: "0.1.0-test", ConnectorID: "cid", Transport: proto.TransportDirect,
		ConnectedPops: func() []string { return []string{"bnk", "fast"} },
		OnHello:       func(h Hello) { ev.mu.Lock(); ev.hello = append(ev.hello, h); ev.mu.Unlock() },
		OnGoaway:      func(g Goaway) { ev.mu.Lock(); ev.goaway = append(ev.goaway, g); ev.mu.Unlock() },
		OnVisible:     func(v Visible) { ev.mu.Lock(); ev.visible = append(ev.visible, v); ev.mu.Unlock() },
		HelloTimeout:  helloTimeout,
	}
	if edit != nil {
		edit(&o)
	}
	s := New(srvConn, o)
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background()) }()
	return s, edgeClient(t, cliConn), done
}

func hello(t *testing.T, cc *http2.ClientConn, extra map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, "https://edge"+proto.PathHello, nil)
	req.Header.Set(proto.HdrProtocol, "1")
	req.Header.Set(proto.HdrEdgeNode, "pop1-edge1")
	req.Header.Set(proto.HdrEdgePop, "bnk")
	req.Header.Set(proto.HdrMaxInflight, "2")
	req.Header.Set(proto.HdrPopsGen, "41")
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	res, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res
}

func TestHelloAndProxiedGet(t *testing.T) {
	var gotHdr http.Header
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHdr = r.Header.Clone()
		gotHdr.Set("Host", r.Host)
		w.Header().Set("Hcdn-Secret", "x")
		w.Header().Set("X-Origin", "1")
		io.WriteString(w, "hello from service")
	}))
	defer svc.Close()
	ev := &events{}
	s, cc, done := start(t, table(t, svc.URL), ev, 0)

	res := hello(t, cc, nil)
	if res.StatusCode != 200 {
		t.Fatalf("hello status %d", res.StatusCode)
	}
	if res.Header.Get(proto.HdrConnVersion) != "0.1.0-test" || res.Header.Get(proto.HdrConnID) != "cid" ||
		res.Header.Get(proto.HdrFeatures) != "ws,owner,visible" || res.Header.Get(proto.HdrConnectedPops) != "bnk,fast" ||
		res.Header.Get(proto.HdrTransport) != proto.TransportDirect ||
		res.Header.Get(proto.HdrOwnerAbsent) != proto.OwnerAbsentNotRequested || res.Header.Get(proto.HdrOwnerTicket) != "" {
		t.Fatalf("hello response headers: %v", res.Header)
	}
	if h := s.Hello(); h == nil || h.EdgeNode != "pop1-edge1" || h.MaxInflight != 2 || h.PopsGen != "41" {
		t.Fatalf("stored hello: %+v", h)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://shop.example.com/a?b=1", nil)
	req.Header.Set(proto.HdrRequestID, "rid-1")
	req.Header.Set(proto.HdrVhost, "shop.example.com")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("X-Real-Ip", "203.0.113.9")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Hcdn-Whatever", "strip me")
	req.Header.Set("X-Hcdn-Vhost", "strip me too")
	res2, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res2.Body)
	res2.Body.Close()
	if res2.StatusCode != 200 || string(body) != "hello from service" {
		t.Fatalf("proxied: %d %q", res2.StatusCode, body)
	}
	if res2.Header.Get(proto.HdrConnectorRT) == "" || res2.Header.Get("Hcdn-Secret") != "" || res2.Header.Get("X-Origin") != "1" {
		t.Fatalf("response headers: %v", res2.Header)
	}
	if gotHdr.Get("Host") != "shop.example.com" || gotHdr.Get(proto.HdrTunnelID) != tid ||
		gotHdr.Get("Hcdn-Request-Id") != "" || gotHdr.Get("Hcdn-Vhost") != "" || gotHdr.Get("Hcdn-Whatever") != "" ||
		gotHdr.Get("X-Hcdn-Vhost") != "" ||
		gotHdr.Get("X-Forwarded-For") != "203.0.113.9" || gotHdr.Get("X-Real-Ip") != "203.0.113.9" ||
		gotHdr.Get("X-Forwarded-Proto") != "https" {
		t.Fatalf("service saw headers: %v", gotHdr)
	}

	// Unknown host -> catch-all http_status:404 with an empty body.
	req3, _ := http.NewRequest(http.MethodGet, "https://other.example.org/", nil)
	req3.Header.Set(proto.HdrRequestID, "rid-2")
	res3, err := cc.RoundTrip(req3)
	if err != nil {
		t.Fatal(err)
	}
	b3, _ := io.ReadAll(res3.Body)
	if res3.StatusCode != 404 || len(b3) != 0 {
		t.Fatalf("catch-all: %d %q", res3.StatusCode, b3)
	}

	s.Close()
	<-done
}

func TestControlRouteExemptFromRequestID(t *testing.T) {
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer svc.Close()
	ev := &events{}
	s, cc, done := start(t, table(t, svc.URL), ev, 0)
	defer func() { s.Close(); <-done }()

	// hello carries no hcdn-request-id and must be accepted.
	if res := hello(t, cc, nil); res.StatusCode != 200 {
		t.Fatalf("hello without request id: %d", res.StatusCode)
	}
	// visitor request without hcdn-request-id -> 400 empty.
	req, _ := http.NewRequest(http.MethodGet, "https://shop.example.com/", nil)
	res, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 400 || len(b) != 0 {
		t.Fatalf("missing request id: %d %q", res.StatusCode, b)
	}
	// A visitor request relayed to the hello path (it carries hcdn-request-id)
	// is neither honored as control nor proxied: 404, and the stored hello is untouched.
	req2, _ := http.NewRequest(http.MethodPost, "https://shop.example.com"+proto.PathHello, nil)
	req2.Header.Set(proto.HdrRequestID, "rid")
	req2.Header.Set(proto.HdrProtocol, "1")
	req2.Header.Set(proto.HdrMaxInflight, "1")
	res2, err := cc.RoundTrip(req2)
	if err != nil {
		t.Fatal(err)
	}
	res2.Body.Close()
	if res2.StatusCode != 404 || s.Hello().MaxInflight != 2 {
		t.Fatalf("visitor request on hello path: %d, max_inflight %d", res2.StatusCode, s.Hello().MaxInflight)
	}
	// Wrong method on a real control route: 405.
	req2b, _ := http.NewRequest(http.MethodGet, "https://edge"+proto.PathGoaway, nil)
	res2b, err := cc.RoundTrip(req2b)
	if err != nil {
		t.Fatal(err)
	}
	res2b.Body.Close()
	if res2b.StatusCode != 405 {
		t.Fatalf("GET on goaway path: %d", res2b.StatusCode)
	}
	// goaway -> 204 and callback.
	req3, _ := http.NewRequest(http.MethodPost, "https://edge"+proto.PathGoaway, nil)
	req3.Header.Set(proto.HdrReason, "cap_exceeded")
	req3.Header.Set(proto.HdrRetryAfter, "7")
	res3, err := cc.RoundTrip(req3)
	if err != nil {
		t.Fatal(err)
	}
	res3.Body.Close()
	if res3.StatusCode != 204 {
		t.Fatalf("goaway: %d", res3.StatusCode)
	}
	waitFor(t, func() bool { ev.mu.Lock(); defer ev.mu.Unlock(); return len(ev.goaway) == 1 })
	if g := ev.goaway[0]; g.Reason != "cap_exceeded" || g.RetryAfter != 7*time.Second {
		t.Fatalf("goaway event: %+v", g)
	}
	// goaway without retry-after uses the default for the reason; unknown reason -> protocol_error.
	req4, _ := http.NewRequest(http.MethodPost, "https://edge"+proto.PathGoaway, nil)
	req4.Header.Set(proto.HdrReason, "disabled")
	res4, _ := cc.RoundTrip(req4)
	res4.Body.Close()
	req5, _ := http.NewRequest(http.MethodPost, "https://edge"+proto.PathGoaway, nil)
	req5.Header.Set(proto.HdrReason, "bogus")
	res5, _ := cc.RoundTrip(req5)
	res5.Body.Close()
	req6, _ := http.NewRequest(http.MethodPost, "https://edge"+proto.PathGoaway, nil)
	req6.Header.Set(proto.HdrReason, "owner_required")
	res6, _ := cc.RoundTrip(req6)
	res6.Body.Close()
	waitFor(t, func() bool { ev.mu.Lock(); defer ev.mu.Unlock(); return len(ev.goaway) == 4 })
	// OnGoaway runs on its own goroutine, so these three can arrive in any order.
	byReason := map[string]Goaway{}
	for _, g := range ev.goaway[1:] {
		byReason[g.Reason] = g
	}
	_, protoErr := byReason[proto.ReasonProtocolError]
	_, owner := byReason[proto.ReasonOwnerRequired]
	if byReason[proto.ReasonDisabled].RetryAfter != 300*time.Second || !protoErr || !owner {
		t.Fatalf("goaway defaults: %+v", ev.goaway)
	}
}

// Every hello answer carries the ticket, or else the no-ticket reason.
func TestHelloOwnerHeaders(t *testing.T) {
	for _, tc := range []struct {
		name, ticket, absent, wantTicket, wantAbsent string
	}{
		{"default", "", "", "", proto.OwnerAbsentNotRequested},
		{"absent", "", proto.OwnerAbsentNoToken, "", proto.OwnerAbsentNoToken},
		{"ticket", "aaa.bbb.ccc", proto.OwnerAbsentNoToken, "aaa.bbb.ccc", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, cc, _ := startOpts(t, table(t, "http://127.0.0.1:1"), &events{}, 0, func(o *Options) {
				o.OwnerTicket, o.OwnerAbsent = tc.ticket, tc.absent
			})
			res := hello(t, cc, nil)
			if res.StatusCode != 200 || res.Header.Get(proto.HdrOwnerTicket) != tc.wantTicket ||
				res.Header.Get(proto.HdrOwnerAbsent) != tc.wantAbsent {
				t.Fatalf("hello answer %d %v", res.StatusCode, res.Header)
			}
			if _, ok := res.Header[proto.HdrOwnerAbsent]; ok == (tc.wantAbsent == "") {
				t.Fatalf("hcdn-owner-absent present=%v, want %q", ok, tc.wantAbsent)
			}
		})
	}
}

func TestHelloTimeoutClosesSession(t *testing.T) {
	ev := &events{}
	s, cc, done := start(t, table(t, "http://127.0.0.1:1"), ev, 200*time.Millisecond)
	_ = cc
	select {
	case err := <-done:
		if err != ErrHelloTimeout {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("session did not close after hello timeout")
	}
	if s.Ready() {
		t.Fatal("session must not be ready")
	}
}

func TestHelloBadProtocolRejected(t *testing.T) {
	ev := &events{}
	_, cc, done := start(t, table(t, "http://127.0.0.1:1"), ev, 0)
	req, _ := http.NewRequest(http.MethodPost, "https://edge"+proto.PathHello, nil)
	req.Header.Set(proto.HdrProtocol, "2")
	res, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("the 400 must reach the edge before the close: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != 400 {
		t.Fatalf("status %d", res.StatusCode)
	}
	select {
	case err := <-done:
		if err != ErrBadHello {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("session did not close")
	}
}

func TestHelloNonPrintableRejected(t *testing.T) {
	for name, h := range map[string]map[string]string{
		"node c1":   {proto.HdrEdgeNode: "\xc2\x9b2Jnode"},
		"pop c1":    {proto.HdrEdgePop: "bnk\xc2\x9d0;x"},
		"gen c1":    {proto.HdrPopsGen: "41\xc2\x85"},
		"node utf8": {proto.HdrEdgeNode: "bad\xffnode"},
		"features":  {proto.HdrEdgeFeatures: "visible\xc2\x9b"},
	} {
		t.Run(name, func(t *testing.T) {
			s, cc, done := start(t, table(t, "http://127.0.0.1:1"), &events{}, 0)
			if res := hello(t, cc, h); res.StatusCode != 400 {
				t.Fatalf("status %d", res.StatusCode)
			}
			select {
			case err := <-done:
				if err != ErrBadHello {
					t.Fatalf("err = %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("session did not close")
			}
			if s.Hello() != nil {
				t.Fatal("hello stored")
			}
		})
	}
}

func TestInflightCapOverloaded(t *testing.T) {
	release := make(chan struct{})
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer svc.Close()
	defer close(release)
	ev := &events{}
	s, cc, done := start(t, table(t, svc.URL), ev, 0)
	defer func() { s.Close(); <-done }()
	hello(t, cc, map[string]string{proto.HdrMaxInflight: "2"})

	results := make(chan *http.Response, 2)
	for i := 0; i < 2; i++ {
		go func() {
			req, _ := http.NewRequest(http.MethodGet, "https://shop.example.com/slow", nil)
			req.Header.Set(proto.HdrRequestID, "rid")
			res, err := cc.RoundTrip(req)
			if err == nil {
				results <- res
			}
		}()
	}
	waitFor(t, func() bool { return s.Inflight() == 2 })
	req, _ := http.NewRequest(http.MethodGet, "https://shop.example.com/third", nil)
	req.Header.Set(proto.HdrRequestID, "rid")
	res, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 502 || res.Header.Get(proto.HdrError) != proto.ErrOverloaded || len(b) != 0 {
		t.Fatalf("overloaded: %d %v %q", res.StatusCode, res.Header, b)
	}
}

func TestDrainSendsGoawayAndCloses(t *testing.T) {
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer svc.Close()
	ev := &events{}
	s, cc, done := start(t, table(t, svc.URL), ev, 0)
	hello(t, cc, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.Drain(ctx)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("drain did not close the session")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://shop.example.com/", nil)
	req.Header.Set(proto.HdrRequestID, "rid")
	if _, err := cc.RoundTrip(req); err == nil {
		t.Fatal("request after drain must fail")
	}
}

// The first bytes from the connector are the server SETTINGS (never the client
// preface) and they carry the limits of docs/protocol.md, section 4.
func TestAdvertisedSettings(t *testing.T) {
	srvConn, cliConn := pair(t)
	s := New(srvConn, Options{Handler: http.NotFoundHandler(), Version: "v", ConnectorID: "c", Transport: proto.TransportDirect})
	go func() { _ = s.Serve(context.Background()) }()
	defer s.Close()
	fr := http2.NewFramer(cliConn, cliConn)
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	sf, ok := f.(*http2.SettingsFrame)
	if !ok {
		t.Fatalf("first frame %T, want SETTINGS", f)
	}
	got := map[http2.SettingID]uint32{}
	_ = sf.ForeachSetting(func(st http2.Setting) error { got[st.ID] = st.Val; return nil })
	if got[http2.SettingMaxConcurrentStreams] != proto.MaxConcurrentStreams {
		t.Fatalf("MAX_CONCURRENT_STREAMS %d", got[http2.SettingMaxConcurrentStreams])
	}
	if got[http2.SettingMaxFrameSize] < proto.MaxFrameSize {
		t.Fatalf("MAX_FRAME_SIZE %d", got[http2.SettingMaxFrameSize])
	}
	if got[http2.SettingMaxHeaderListSize] < proto.MaxHeaderBytes {
		t.Fatalf("MAX_HEADER_LIST_SIZE %d", got[http2.SettingMaxHeaderListSize])
	}
}

// A supervisor cancel (SIGTERM) must not abort in-flight streams: Drain
// finishes them and only then closes the connection.
func TestDrainCompletesInflightAfterContextCancel(t *testing.T) {
	release := make(chan struct{})
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
			io.WriteString(w, "late")
		case <-r.Context().Done():
		}
	}))
	defer svc.Close()
	srvConn, cliConn := pair(t)
	s := New(srvConn, Options{Handler: ingress.NewHandler(table(t, svc.URL), tid, slog.Default(), nil),
		Version: "0.1.0-test", ConnectorID: "cid", Transport: proto.TransportDirect})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	cc := edgeClient(t, cliConn)
	hello(t, cc, nil)

	type result struct {
		res *http.Response
		err error
	}
	got := make(chan result, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodGet, "https://shop.example.com/slow", nil)
		req.Header.Set(proto.HdrRequestID, "rid")
		res, err := cc.RoundTrip(req)
		got <- result{res, err}
	}()
	waitFor(t, func() bool { return s.Inflight() == 1 })
	cancel()
	drained := make(chan struct{})
	go func() { s.Drain(context.Background()); close(drained) }()
	time.Sleep(100 * time.Millisecond)
	select {
	case r := <-got:
		t.Fatalf("stream ended before the service answered: %v %v", r.res, r.err)
	default:
	}
	close(release)
	r := <-got
	if r.err != nil {
		t.Fatal(r.err)
	}
	body, _ := io.ReadAll(r.res.Body)
	if r.res.StatusCode != 200 || string(body) != "late" {
		t.Fatalf("in-flight request: %d %q", r.res.StatusCode, body)
	}
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("drain did not finish")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("session did not close after drain")
	}
}

// Before hello nothing is in flight, so a cancel closes the session at once.
func TestContextCancelBeforeHelloCloses(t *testing.T) {
	srvConn, _ := pair(t)
	s := New(srvConn, Options{Handler: http.NotFoundHandler(), Version: "v", ConnectorID: "c", Transport: proto.TransportDirect})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("session did not close")
	}
}

func TestWebSocketBridge(t *testing.T) {
	echo := newUpgradeEcho(t)
	defer echo.Close()
	ev := &events{}
	s, cc, done := start(t, table(t, echo.URL), ev, 0)
	defer func() { s.Close(); <-done }()
	hello(t, cc, nil)

	pr, pw := io.Pipe()
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: "shop.example.com"},
		Host:   "shop.example.com",
		Header: http.Header{},
		Body:   pr,
	}
	req.Header.Set(proto.HdrRequestID, "rid-ws")
	req.Header.Set(proto.HdrUpgrade, "websocket")
	req.Header.Set(proto.HdrPath, "/ws?room=1")
	req.Header.Set("Sec-Websocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-Websocket-Version", "13")
	req.Header.Set("Sec-Websocket-Protocol", "chat")
	req.Header.Set("Origin", "https://shop.example.com")
	res, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("CONNECT status %d %v", res.StatusCode, res.Header)
	}
	if res.Header.Get(proto.HdrWSAccept) != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" || res.Header.Get(proto.HdrWSProtocol) != "chat" {
		t.Fatalf("ws headers: %v", res.Header)
	}
	if got := echo.lastReq(); got.URL.RequestURI() != "/ws?room=1" || got.Header.Get("Upgrade") != "websocket" ||
		got.Header.Get(proto.HdrTunnelID) != tid || got.Header.Get(proto.HdrPath) != "" || got.Header.Get("Origin") == "" {
		t.Fatalf("service upgrade request: %v %v", got.URL, got.Header)
	}
	for _, msg := range []string{"ping-1", "ping-2", strings.Repeat("x", 70000)} {
		if _, err := io.WriteString(pw, msg); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(res.Body, buf); err != nil {
			t.Fatal(err)
		}
		if string(buf) != msg {
			t.Fatalf("echo mismatch (%d bytes)", len(msg))
		}
	}
	pw.Close()
	if _, err := io.ReadAll(res.Body); err != nil {
		t.Fatalf("stream did not end cleanly: %v", err)
	}
}

func TestGoawayRetryAfterClamp(t *testing.T) {
	cases := []struct {
		reason, value string
		want          time.Duration
	}{
		{proto.ReasonCapExceeded, "-5", proto.DefaultRetryAfterCapExceeded},
		{proto.ReasonCapExceeded, "abc", proto.DefaultRetryAfterCapExceeded},
		{proto.ReasonCapExceeded, "99999999", proto.MaxRetryAfterShort},
		{proto.ReasonAuthUnavailable, "3600", proto.MaxRetryAfterShort},
		{proto.ReasonDisabled, "99999999999999999999", proto.DefaultRetryAfterDisabled}, // int64 overflow
		{proto.ReasonDisabled, "86400", proto.MaxPause},
		{proto.ReasonDisabled, "0", proto.DefaultRetryAfterDisabled},
		{proto.ReasonDisabled, "42", 42 * time.Second},
		{proto.ReasonDrain, "abc", 0},
	}
	for _, c := range cases {
		if got, _ := parseRetryAfter(c.reason, c.value); got != c.want {
			t.Errorf("%s %q: got %v want %v", c.reason, c.value, got, c.want)
		}
	}
	// End to end: the clamped value reaches the goaway callback.
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer svc.Close()
	ev := &events{}
	s, cc, done := start(t, table(t, svc.URL), ev, 0)
	defer func() { s.Close(); <-done }()
	req, _ := http.NewRequest(http.MethodPost, "https://edge"+proto.PathGoaway, nil)
	req.Header.Set(proto.HdrReason, proto.ReasonCapExceeded)
	req.Header.Set(proto.HdrRetryAfter, "99999999999999999999")
	res, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	waitFor(t, func() bool { ev.mu.Lock(); defer ev.mu.Unlock(); return len(ev.goaway) == 1 })
	if ev.goaway[0].RetryAfter != proto.DefaultRetryAfterCapExceeded {
		t.Fatalf("overflowing retry-after: %v", ev.goaway[0].RetryAfter)
	}
}

// wsConnect opens a CONNECT stream; body must be closable (the h2 client
// unblocks a pending body Read only through Body.Close).
func wsConnect(t *testing.T, cc *http2.ClientConn, body io.ReadCloser, extra map[string]string) *http.Response {
	t.Helper()
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: "shop.example.com"},
		Host:   "shop.example.com",
		Header: http.Header{},
		Body:   body,
	}
	req.Header.Set(proto.HdrRequestID, "rid-ws")
	req.Header.Set(proto.HdrUpgrade, "websocket")
	req.Header.Set(proto.HdrPath, "/ws")
	req.Header.Set("Sec-Websocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-Websocket-Version", "13")
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	res, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestWebSocketStripsExtensionsAndDefaultUA(t *testing.T) {
	echo := newUpgradeEcho(t)
	defer echo.Close()
	ev := &events{}
	s, cc, done := start(t, table(t, echo.URL), ev, 0)
	defer func() { s.Close(); <-done }()
	hello(t, cc, nil)
	pr, pw := io.Pipe()
	// An empty User-Agent makes the h2 test client omit its own default, like tunneld.
	res := wsConnect(t, cc, pr, map[string]string{"Sec-Websocket-Extensions": "permessage-deflate", "User-Agent": ""})
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	got := echo.lastReq()
	if got.Header.Get("Sec-Websocket-Extensions") != "" {
		t.Fatal("Sec-WebSocket-Extensions must not reach the service (never echoed to the visitor)")
	}
	if _, ok := got.Header["User-Agent"]; ok {
		t.Fatalf("Go's default User-Agent leaked: %q", got.Header.Get("User-Agent"))
	}
	pw.Close()
	io.ReadAll(res.Body)
}

func TestWebSocketCloseOrderAndGoroutines(t *testing.T) {
	echo := newUpgradeEcho(t)
	defer echo.Close()
	ev := &events{}
	s, cc, done := start(t, table(t, echo.URL), ev, 0)
	defer func() { s.Close(); <-done }()
	hello(t, cc, nil)

	// Warm up once so lazily started goroutines (transport, pools) do not skew the count.
	pr, pw := io.Pipe()
	res := wsConnect(t, cc, pr, nil)
	pw.Close()
	io.ReadAll(res.Body)
	waitFor(t, func() bool { return echo.closed.Load() == 1 })
	settle := func() int {
		var n int
		for i := 0; i < 50; i++ {
			n = runtime.NumGoroutine()
			time.Sleep(20 * time.Millisecond)
			if runtime.NumGoroutine() == n {
				break
			}
		}
		return n
	}
	before := settle()

	// Service closes first: the stream ends cleanly after the echoed bytes.
	echo.setCloseAfter(5)
	pr, pw = io.Pipe()
	res = wsConnect(t, cc, pr, nil)
	go io.WriteString(pw, "hello world")
	b, err := io.ReadAll(res.Body)
	if err != nil || string(b) != "hello" {
		t.Fatalf("service-first close: %q %v", b, err)
	}
	pw.Close()
	echo.setCloseAfter(0)
	waitFor(t, func() bool { return echo.closed.Load() == 2 })

	// Edge resets first (RST_STREAM from Body.Close): the connector closes the service conn.
	pr, pw = io.Pipe()
	res = wsConnect(t, cc, pr, nil)
	io.WriteString(pw, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(res.Body, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo before reset: %q %v", buf, err)
	}
	res.Body.Close()
	waitFor(t, func() bool { return echo.closed.Load() == 3 })
	pw.Close()

	after := settle()
	if after > before {
		t.Fatalf("goroutines leaked: %d -> %d", before, after)
	}
}

func TestWebSocketNon101ReturnsResponse(t *testing.T) {
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Hcdn-Leak", "1")
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, "nope")
	}))
	defer svc.Close()
	ev := &events{}
	s, cc, done := start(t, table(t, svc.URL), ev, 0)
	defer func() { s.Close(); <-done }()
	hello(t, cc, nil)
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: "shop.example.com"}, Host: "shop.example.com", Header: http.Header{}}
	req.Header.Set(proto.HdrRequestID, "rid-ws")
	req.Header.Set(proto.HdrUpgrade, "websocket")
	res, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 403 || string(b) != "nope" || res.Header.Get("Hcdn-Leak") != "" || res.Header.Get(proto.HdrConnectorRT) == "" {
		t.Fatalf("non-101: %d %q %v", res.StatusCode, b, res.Header)
	}
	// CONNECT to an unreachable service -> 502 service_unreachable.
	s2, cc2, done2 := start(t, table(t, "http://127.0.0.1:1"), ev, 0)
	defer func() { s2.Close(); <-done2 }()
	hello(t, cc2, nil)
	res2, err := cc2.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	res2.Body.Close()
	if res2.StatusCode != 502 || res2.Header.Get(proto.HdrError) != proto.ErrServiceUnreachable {
		t.Fatalf("unreachable ws: %d %v", res2.StatusCode, res2.Header)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

func visibleReq(t *testing.T, cc *http2.ClientConn, method string, hdr map[string]string) int {
	t.Helper()
	req, _ := http.NewRequest(method, "https://edge"+proto.PathVisible, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

func TestHelloEdgeFeatures(t *testing.T) {
	ev := &events{}
	s, cc, done := start(t, table(t, "http://127.0.0.1:1"), ev, 0)
	defer func() { s.Close(); <-done }()
	if res := hello(t, cc, map[string]string{proto.HdrEdgeFeatures: " Visible , ws,,"}); res.StatusCode != 200 {
		t.Fatalf("hello %d", res.StatusCode)
	}
	h := s.Hello()
	if len(h.EdgeFeatures) != 2 || h.EdgeFeatures[0] != "visible" || h.EdgeFeatures[1] != "ws" ||
		!h.HasEdgeFeature(proto.EdgeFeatureVisible) || h.HasEdgeFeature("owner") {
		t.Fatalf("features %q", h.EdgeFeatures)
	}

	s2, cc2, done2 := start(t, table(t, "http://127.0.0.1:1"), &events{}, 0)
	defer func() { s2.Close(); <-done2 }()
	hello(t, cc2, nil)
	if h := s2.Hello(); h.EdgeFeatures != nil || h.HasEdgeFeature(proto.EdgeFeatureVisible) {
		t.Fatalf("no header: %q", h.EdgeFeatures)
	}
}

func TestVisibleControlRoute(t *testing.T) {
	var proxied atomic.Int64
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxied.Add(1) }))
	defer svc.Close()
	ev := &events{}
	s, cc, done := start(t, table(t, svc.URL), ev, 0)
	defer func() { s.Close(); <-done }()

	// Before hello the session has nothing to confirm.
	if code := visibleReq(t, cc, http.MethodPost, map[string]string{proto.HdrVisibleScope: "pop"}); code != 400 {
		t.Fatalf("visible before hello: %d", code)
	}
	hello(t, cc, map[string]string{proto.HdrEdgeFeatures: "visible"})

	// A visitor request relayed to the visible path: 404, never proxied, no signal.
	if code := visibleReq(t, cc, http.MethodPost, map[string]string{
		proto.HdrRequestID: "rid", proto.HdrVhost: "shop.example.com", proto.HdrVisibleScope: "pop"}); code != 404 {
		t.Fatalf("visitor request on visible path: %d", code)
	}
	if code := visibleReq(t, cc, http.MethodGet, map[string]string{proto.HdrVisibleScope: "pop"}); code != 405 {
		t.Fatalf("GET: %d", code)
	}
	for _, scope := range []string{"", "session", "pops", "pop,node"} {
		if code := visibleReq(t, cc, http.MethodPost, map[string]string{proto.HdrVisibleScope: scope}); code != 400 {
			t.Fatalf("scope %q: %d", scope, code)
		}
	}
	ev.mu.Lock()
	n := len(ev.visible)
	ev.mu.Unlock()
	if n != 0 || proxied.Load() != 0 {
		t.Fatalf("visible events %d, proxied %d", n, proxied.Load())
	}

	if code := visibleReq(t, cc, http.MethodPost, map[string]string{proto.HdrVisibleScope: " POP "}); code != 204 {
		t.Fatalf("visible pop: %d", code)
	}
	// A second signal gets 204 too, but OnVisible runs once per session.
	if code := visibleReq(t, cc, http.MethodPost, map[string]string{proto.HdrVisibleScope: "node"}); code != 204 {
		t.Fatalf("second visible: %d", code)
	}
	ev.mu.Lock()
	defer ev.mu.Unlock()
	if len(ev.visible) != 1 || ev.visible[0].Scope != proto.VisibleScopePop || ev.visible[0].EdgeNode != "pop1-edge1" ||
		ev.visible[0].At.IsZero() {
		t.Fatalf("visible events %+v", ev.visible)
	}
	if proxied.Load() != 0 {
		t.Fatal("a control request reached the service")
	}
}
