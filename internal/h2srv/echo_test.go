package h2srv

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
)

// upgradeEcho is a minimal WebSocket-style server: it completes the HTTP/1.1
// Upgrade handshake and then echoes raw bytes. Frames are opaque to the bridge.
type upgradeEcho struct {
	URL        string
	ln         net.Listener
	closeAfter int // bytes to echo before the service closes first (0 = never)
	closed     atomic.Int32
	mu         sync.Mutex
	req        *http.Request
}

func newUpgradeEcho(t *testing.T) *upgradeEcho {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &upgradeEcho{URL: "http://" + ln.Addr().String(), ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go e.serve(c)
		}
	}()
	return e
}

func (e *upgradeEcho) Close() { e.ln.Close() }

func (e *upgradeEcho) lastReq() *http.Request {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.req
}

func (e *upgradeEcho) serve(c net.Conn) {
	defer e.closed.Add(1)
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	e.mu.Lock()
	e.req = req
	e.mu.Unlock()
	if req.Header.Get("Upgrade") != "websocket" {
		io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return
	}
	h := sha1.New()
	io.WriteString(h, req.Header.Get("Sec-WebSocket-Key")+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n"
	if p := req.Header.Get("Sec-WebSocket-Protocol"); p != "" {
		resp += "Sec-WebSocket-Protocol: " + p + "\r\n"
	}
	io.WriteString(c, resp+"\r\n")
	e.mu.Lock()
	n := e.closeAfter
	e.mu.Unlock()
	if n > 0 {
		io.CopyN(c, br, int64(n))
		return
	}
	io.Copy(c, br)
}

func (e *upgradeEcho) setCloseAfter(n int) {
	e.mu.Lock()
	e.closeAfter = n
	e.mu.Unlock()
}
