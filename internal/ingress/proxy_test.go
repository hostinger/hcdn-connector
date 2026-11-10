package ingress

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/hostinger/hcdn-connector/internal/metrics"
	"github.com/hostinger/hcdn-connector/internal/proto"
	"github.com/hostinger/hcdn-connector/pkg/config"
	"github.com/hostinger/hcdn-connector/pkg/localguard"
)

func handlerFor(t testing.TB, service string, o config.OriginRequest) *Handler {
	t.Helper()
	if o.ConnectTimeout == 0 {
		o.ConnectTimeout = time.Second
	}
	if o.ResponseHeaderTimeout == 0 {
		o.ResponseHeaderTimeout = time.Second
	}
	if o.KeepaliveConnections == 0 {
		o.KeepaliveConnections = 2
	}
	tbl, err := Build([]config.IngressRule{
		{Hostname: "shop.example.com", Service: service, OriginRequest: o},
		{Service: "http_status:404"},
	}, tid, &localguard.Guard{})
	if err != nil {
		t.Fatal(err)
	}
	return NewHandler(tbl, tid, slog.Default(), metrics.New())
}

func do(h *Handler, method, path string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://shop.example.com"+path, nil)
	req.Header.Set(proto.HdrRequestID, "rid")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func assertErr(t *testing.T, rec *httptest.ResponseRecorder, reason string) {
	t.Helper()
	if rec.Code != 502 || rec.Header().Get(proto.HdrError) != reason || rec.Body.Len() != 0 {
		t.Fatalf("want 502 %s empty; got %d %v %q", reason, rec.Code, rec.Header(), rec.Body.String())
	}
}

func TestErrorHandlerDialError(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	h := handlerFor(t, "http://"+addr, config.OriginRequest{})
	assertErr(t, do(h, "GET", "/", nil), proto.ErrServiceUnreachable)
}

func TestErrorHandlerHeaderTimeout(t *testing.T) {
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer svc.Close()
	h := handlerFor(t, svc.URL, config.OriginRequest{ResponseHeaderTimeout: 100 * time.Millisecond})
	assertErr(t, do(h, "GET", "/", nil), proto.ErrServiceTimeout)
}

func TestErrorHandlerMalformedResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				io.WriteString(c, "garbage not http\r\n\r\n")
				c.Close()
			}()
		}
	}()
	h := handlerFor(t, "http://"+ln.Addr().String(), config.OriginRequest{})
	assertErr(t, do(h, "GET", "/", nil), proto.ErrBadGateway)
}

func TestErrorHandlerTLSToPlaintext(t *testing.T) {
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer svc.Close()
	h := handlerFor(t, "https://"+strings.TrimPrefix(svc.URL, "http://"), config.OriginRequest{NoTLSVerify: true})
	assertErr(t, do(h, "GET", "/", nil), proto.ErrServiceUnreachable)
}

func TestHeaderHygieneAndHostOverride(t *testing.T) {
	var seen http.Header
	var seenHost string
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, seenHost = r.Header.Clone(), r.Host
		w.Header().Set("Hcdn-Internal", "x")
		w.Header().Set("X-Hcdn-Internal", "y")
		w.Header().Set("Keep", "1")
		w.WriteHeader(201)
	}))
	defer svc.Close()
	h := handlerFor(t, svc.URL, config.OriginRequest{HTTPHostHeader: "internal.app"})
	rec := do(h, "POST", "/p?q=1", map[string]string{
		"Hcdn-Vhost":        "shop.example.com",
		"X-Hcdn-Anything":   "z",
		"X-Forwarded-For":   "198.51.100.7, 203.0.113.1",
		"X-Forwarded-Proto": "https",
		"X-Real-Ip":         "198.51.100.7",
		"Connection":        "close, X-Hop",
		"X-Hop":             "1",
		"Te":                "trailers",
	})
	if rec.Code != 201 {
		t.Fatalf("status %d", rec.Code)
	}
	if rec.Header().Get("Hcdn-Internal") != "" || rec.Header().Get("X-Hcdn-Internal") != "" || rec.Header().Get("Keep") != "1" {
		t.Fatalf("response hygiene: %v", rec.Header())
	}
	if rec.Header().Get(proto.HdrConnectorRT) == "" {
		t.Fatal("hcdn-connector-rt missing")
	}
	if seenHost != "internal.app" {
		t.Fatalf("host override: %q", seenHost)
	}
	for _, k := range []string{"Hcdn-Request-Id", "Hcdn-Vhost", "X-Hcdn-Anything", "X-Hop"} {
		if seen.Get(k) != "" {
			t.Fatalf("%s leaked to the service", k)
		}
	}
	if seen.Get("X-Forwarded-For") != "198.51.100.7, 203.0.113.1" {
		t.Fatalf("XFF must pass as received, got %q", seen.Get("X-Forwarded-For"))
	}
	if seen.Get("X-Forwarded-Proto") != "https" || seen.Get("X-Real-Ip") != "198.51.100.7" || seen.Get(proto.HdrTunnelID) != tid {
		t.Fatalf("forwarding headers: %v", seen)
	}
}

func TestPrepareServiceHeadersDropsVisitorForwarding(t *testing.T) {
	in := http.Header{
		"X-Forwarded-Host": {"evil.example"},
		"Forwarded":        {"host=evil.example"},
		"X-Forwarded-For":  {"198.51.100.7"},
	}
	out := in.Clone() // the WebSocket path starts from a clone of the edge request
	PrepareServiceHeaders(out, in, tid)
	if out.Get("X-Forwarded-Host") != "" || out.Get("Forwarded") != "" || out.Get("X-Forwarded-For") != "198.51.100.7" {
		t.Fatalf("forwarding headers: %v", out)
	}
}

func TestNoForwardedHeadersAdded(t *testing.T) {
	var seen http.Header
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = r.Header.Clone() }))
	defer svc.Close()
	h := handlerFor(t, svc.URL, config.OriginRequest{})
	do(h, "GET", "/", nil)
	if _, ok := seen["X-Forwarded-For"]; ok {
		t.Fatal("ReverseProxy must not invent X-Forwarded-For")
	}
}

func TestStatusServiceEmptyBody(t *testing.T) {
	h := handlerFor(t, "http_status:503", config.OriginRequest{})
	rec := do(h, "GET", "/", nil)
	if rec.Code != 503 || rec.Body.Len() != 0 {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
	req := httptest.NewRequest("GET", "https://nobody.example.net/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 404 || rec.Body.Len() != 0 {
		t.Fatalf("catch-all %d %q", rec.Code, rec.Body.String())
	}
}

func TestConnectWithoutWebsocketNotImplemented(t *testing.T) {
	h := handlerFor(t, "http://127.0.0.1:1", config.OriginRequest{})
	req := &http.Request{Method: http.MethodConnect, Host: "shop.example.com", Header: http.Header{}, URL: &url.URL{Host: "shop.example.com"}}
	req.Header.Set(proto.HdrRequestID, "rid")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 501 {
		t.Fatalf("%d", rec.Code)
	}
}

// rawService answers every connection with resp after reading the request head, then closes.
func rawService(t *testing.T, resp string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = http.ReadRequest(bufio.NewReader(c))
				io.WriteString(c, resp)
			}()
		}
	}()
	return "http://" + ln.Addr().String()
}

func connectWS(h *Handler) *httptest.ResponseRecorder { return connectWSCtx(context.Background(), h) }

func connectWSCtx(ctx context.Context, h *Handler) *httptest.ResponseRecorder {
	req := &http.Request{Method: http.MethodConnect, Host: "shop.example.com", Header: http.Header{}, URL: &url.URL{Host: "shop.example.com"}, Body: http.NoBody}
	req.Header.Set(proto.HdrRequestID, "rid")
	req.Header.Set(proto.HdrUpgrade, "websocket")
	req.Header.Set(proto.HdrPath, "/ws")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const wsAccept = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"

func TestWebSocketResponseHeadLimit(t *testing.T) {
	over := rawService(t, wsAccept+"X-Big: "+strings.Repeat("a", proto.MaxHeaderBytes)+"\r\n\r\n")
	assertErr(t, connectWS(handlerFor(t, over, config.OriginRequest{})), proto.ErrBadGateway)

	// A head under the limit works, and the limit lifts for the WebSocket bytes after it.
	payload := strings.Repeat("f", proto.MaxHeaderBytes)
	under := rawService(t, wsAccept+"X-Big: "+strings.Repeat("a", 60<<10)+"\r\n\r\n"+payload)
	rec := connectWS(handlerFor(t, under, config.OriginRequest{}))
	if rec.Code != 200 || rec.Body.String() != payload {
		t.Fatalf("got %d, body %d bytes", rec.Code, rec.Body.Len())
	}
}

func TestWebSocketEdgeCancelIsNotAServiceError(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	h := handlerFor(t, "http://"+addr, config.OriginRequest{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec := connectWSCtx(ctx, h)
	if rec.Header().Get(proto.HdrError) != "" {
		t.Fatalf("an edge cancel must not be reported as %q", rec.Header().Get(proto.HdrError))
	}
	if got := testutil.ToFloat64(h.Metrics.Requests.WithLabelValues("canceled")); got != 1 {
		t.Fatalf("requests{canceled} = %v", got)
	}
}

func TestWebSocket101WithoutAcceptIsBadGateway(t *testing.T) {
	svc := rawService(t, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	assertErr(t, connectWS(handlerFor(t, svc, config.OriginRequest{})), proto.ErrBadGateway)
}

func TestWebSocketSkipsEarlyHints(t *testing.T) {
	svc := rawService(t, "HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n"+
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
	rec := connectWS(handlerFor(t, svc, config.OriginRequest{}))
	if rec.Code != 200 || rec.Header().Get(proto.HdrWSAccept) != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("got %d %v", rec.Code, rec.Header())
	}
}

func TestHTTP2TransportKeepsWebSocketDialOnHTTP1(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	h := handlerFor(t, origin.URL, config.OriginRequest{NoTLSVerify: true, HTTP2: true})
	if rec := do(h, "GET", "/", nil); rec.Code != 200 {
		t.Fatalf("GET over h2: %d", rec.Code)
	}
	c, err := h.Table.Match("shop.example.com").Service.dialRaw(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// The h2-only test server leaves ALPN empty for an http/1.1-only offer.
	if got := c.(*tls.Conn).ConnectionState().NegotiatedProtocol; got == "h2" {
		t.Fatal("WebSocket dial negotiated h2 after an h2 request")
	}
}

func TestWSTargetKeepsPathByteExact(t *testing.T) {
	cases := []struct{ svc, path, want string }{
		{"http://10.0.0.1:8080", "/ws?room=1", "/ws?room=1"},
		{"http://10.0.0.1:8080", "/a%2Fb/c%20d?x=%2F", "/a%2Fb/c%20d?x=%2F"},
		{"http://10.0.0.1:8080/app/", "/a%2Fb?x=1", "/app/a%2Fb?x=1"},
		{"http://10.0.0.1:8080/app", "/", "/app/"},
		{"http://10.0.0.1:8080/", "/plain", "/plain"},
	}
	for _, c := range cases {
		u, _ := url.Parse(c.svc)
		target, err := wsTarget(u, c.path)
		if err != nil {
			t.Fatalf("%s + %s: %v", c.svc, c.path, err)
		}
		if got := target.RequestURI(); got != c.want {
			t.Errorf("%s + %s: got %s want %s", c.svc, c.path, got, c.want)
		}
	}
	u, _ := url.Parse("http://10.0.0.1:8080")
	for _, bad := range []string{"ws", "http://evil/", "//host/x"} {
		if _, err := wsTarget(u, bad); err == nil && bad != "//host/x" {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassify(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{&net.OpError{Op: "dial", Err: errors.New("connection refused")}, proto.ErrServiceUnreachable},
		{&net.OpError{Op: "dial", Err: timeoutErr{}}, proto.ErrServiceUnreachable},
		{&net.OpError{Op: "read", Err: errors.New("connection reset by peer")}, proto.ErrBadGateway},
		{timeoutErr{}, proto.ErrServiceTimeout},
		{context.DeadlineExceeded, proto.ErrServiceTimeout},
		{errors.New("net/http: TLS handshake timeout"), proto.ErrServiceUnreachable},
		{&net.OpError{Op: "remote error", Err: errors.New("tls: handshake failure")}, proto.ErrServiceUnreachable},
		{io.ErrUnexpectedEOF, proto.ErrBadGateway},
		{errors.New("malformed HTTP response"), proto.ErrBadGateway},
	}
	for _, c := range cases {
		if got := Classify(c.err); got != c.want {
			t.Errorf("%v: got %s want %s", c.err, got, c.want)
		}
	}
}

func FuzzStripControlHeaders(f *testing.F) {
	f.Add("Hcdn-Request-Id", "abc")
	f.Add("x-hcdn-vhost", "shop")
	f.Add("HCDN-", "")
	f.Add("Accept", "*/*")
	f.Add("hcd", "n")
	f.Fuzz(func(t *testing.T, name, value string) {
		const keep = "X-Fuzz-Keep"
		if strings.EqualFold(name, keep) {
			return
		}
		h := http.Header{}
		h[name] = []string{value}
		h.Set(keep, "1")
		StripControlHeaders(h)
		for k := range h {
			if IsControlHeader(k) {
				t.Fatalf("control header %q survived", k)
			}
		}
		if h.Get(keep) != "1" {
			t.Fatal("unrelated header removed")
		}
		out := h.Clone()
		PrepareServiceHeaders(out, h, tid)
		if out.Get(proto.HdrTunnelID) != tid {
			t.Fatal("tunnel id missing")
		}
		for k := range out {
			if IsControlHeader(k) && k != proto.HdrTunnelID {
				t.Fatalf("control header %q in service request", k)
			}
		}
	})
}

// The guard holds at dial time for both dialers, the HTTP transport and the
// WebSocket dial: a blocked port on this machine answers service_unreachable
// with a warning, and no connection is attempted.
func TestGuardRefusesBlockedLocalPorts(t *testing.T) {
	for _, svc := range []string{"http://127.0.0.1:6379", "https://[::1]:9229", "http://0.0.0.0:22"} {
		var logs strings.Builder
		tbl, err := Build([]config.IngressRule{
			{Hostname: "shop.example.com", Service: svc, OriginRequest: config.OriginRequest{
				ConnectTimeout: time.Second, ResponseHeaderTimeout: time.Second, KeepaliveConnections: 2}},
			{Service: "http_status:404"},
		}, tid, &localguard.Guard{})
		if err != nil {
			t.Fatal(err)
		}
		h := NewHandler(tbl, tid, slog.New(slog.NewTextHandler(&logs, nil)), metrics.New())
		assertErr(t, do(h, "GET", "/", nil), proto.ErrServiceUnreachable)
		assertErr(t, connectWS(h), proto.ErrServiceUnreachable)
		if n := strings.Count(logs.String(), "refused a dial to a sensitive local port"); n != 2 {
			t.Errorf("%s: %d warnings, want 2:\n%s", svc, n, logs.String())
		}

		s := tbl.Rules[0].Service
		u, _ := url.Parse(svc)
		if _, err := s.Transport.DialContext(context.Background(), "tcp", u.Host); !errors.Is(err, localguard.ErrBlocked) {
			t.Errorf("%s: transport dial err = %v, want ErrBlocked", svc, err)
		}
		if _, err := s.dialRaw(context.Background()); !errors.Is(err, localguard.ErrBlocked) {
			t.Errorf("%s: WebSocket dial err = %v, want ErrBlocked", svc, err)
		}
	}

	// Without a guard (nil), the same dial reaches the network.
	s, err := NewService("http://127.0.0.1:6379", config.OriginRequest{ConnectTimeout: time.Second}, tid, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := s.Transport.DialContext(context.Background(), "tcp", "127.0.0.1:6379")
	if errors.Is(err, localguard.ErrBlocked) {
		t.Fatal("a nil guard refused the dial")
	}
	if conn != nil {
		conn.Close()
	}
}
