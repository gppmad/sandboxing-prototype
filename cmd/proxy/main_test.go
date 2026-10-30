package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// serve runs handleConn on one end of an in-memory pipe and returns the other
// end, so a test is a whole client with no real proxy socket.
func serve(allowlist []string) net.Conn {
	client, server := net.Pipe()
	go handleConn(server, allowlist)
	return client
}

func status(t *testing.T, c net.Conn) int {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp.StatusCode
}

// The property the whole leak bug came down to: the proxy's own headers must
// be consumed, so the first byte the target sees is the tunnel payload.
func TestConnectRelaysOnlyThePayload(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	got := make(chan string, 1)
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c)
		got <- string(b)
	}()

	const payload = "\x16\x03\x01 pretend this is a TLS ClientHello"
	c := serve([]string{"127.0.0.1"})
	go fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %[1]s\r\nProxy-Connection: Keep-Alive\r\nUser-Agent: curl/8.4.0\r\n\r\n", backend.Addr())

	// Read the 200 off the pipe byte-exact so nothing of the payload is consumed.
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT response = %v, %v; want 200", resp, err)
	}
	fmt.Fprint(c, payload)
	c.Close()

	if s := <-got; s != payload {
		t.Errorf("target received %q, want %q", s, payload)
	}
}

func TestConnectRefusesHostNotInAllowlist(t *testing.T) {
	c := serve([]string{"example.com"})
	defer c.Close()
	go fmt.Fprint(c, "CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\n\r\n")

	if got := status(t, c); got != http.StatusForbidden {
		t.Errorf("status = %d, want 403", got)
	}
}

func TestPlainHTTPRefusesHostNotInAllowlist(t *testing.T) {
	c := serve([]string{"example.com"})
	defer c.Close()
	go fmt.Fprint(c, "GET http://evil.com/ HTTP/1.1\r\nHost: evil.com\r\n\r\n")

	if got := status(t, c); got != http.StatusForbidden {
		t.Errorf("status = %d, want 403", got)
	}
}

// With an empty allowlist everything is refused (default deny).
func TestPlainHTTPRefusedWithEmptyAllowlist(t *testing.T) {
	c := serve(nil)
	defer c.Close()
	go fmt.Fprint(c, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")

	if got := status(t, c); got != http.StatusForbidden {
		t.Errorf("status = %d, want 403", got)
	}
}

// The whole point: an allowed host's response comes back to the client as is.
func TestPlainHTTPRelaysTheResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "yes")
		w.WriteHeader(http.StatusTeapot)
		fmt.Fprint(w, "short and stout")
	}))
	defer backend.Close()

	c := serve([]string{"127.0.0.1"})
	defer c.Close()
	go fmt.Fprintf(c, "GET %s/x HTTP/1.1\r\nHost: %s\r\n\r\n", backend.URL, backend.Listener.Addr())

	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusTeapot || string(body) != "short and stout" || resp.Header.Get("X-Backend") != "yes" {
		t.Errorf("got %d %q X-Backend=%q; want the backend's own response",
			resp.StatusCode, body, resp.Header.Get("X-Backend"))
	}
}

// POST bodies must make it to the backend too.
func TestPlainHTTPForwardsRequestBody(t *testing.T) {
	got := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- string(b)
	}))
	defer backend.Close()

	c := serve([]string{"127.0.0.1"})
	defer c.Close()
	go fmt.Fprintf(c, "POST %s/ HTTP/1.1\r\nHost: %s\r\nContent-Length: 5\r\n\r\nhello", backend.URL, backend.Listener.Addr())
	status(t, c)

	if b := <-got; b != "hello" {
		t.Errorf("backend received body %q, want hello", b)
	}
}

// The backend must receive an ordinary origin-form request: the path and the
// client's own headers, but nothing that was addressed to the proxy.
func TestPlainHTTPForwardsRequestWithoutProxyHeaders(t *testing.T) {
	got := make(chan *http.Request, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r
	}))
	defer backend.Close()

	c := serve([]string{"127.0.0.1"})
	defer c.Close()
	go fmt.Fprintf(c, "GET %s/hello?x=1 HTTP/1.1\r\nHost: %s\r\n"+
		"Proxy-Connection: Keep-Alive\r\nProxy-Authorization: Basic c2VjcmV0\r\n"+
		"Connection: X-Secret\r\nX-Secret: hunter2\r\nX-Keep: yes\r\n\r\n",
		backend.URL, backend.Listener.Addr())
	status(t, c) // wait until the proxy is done with the request

	r := <-got
	if r.RequestURI != "/hello?x=1" {
		t.Errorf("backend saw %q, want /hello?x=1", r.RequestURI)
	}
	for _, h := range []string{"Proxy-Connection", "Proxy-Authorization", "X-Secret"} {
		if v := r.Header.Get(h); v != "" {
			t.Errorf("backend received %s: %q", h, v)
		}
	}
	if r.Header.Get("X-Keep") != "yes" {
		t.Error("an ordinary header was dropped")
	}
}

func TestPlainHTTPUnreachableHostGets502(t *testing.T) {
	// Take a free port, then close it so nothing is listening there.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	c := serve([]string{"127.0.0.1"})
	defer c.Close()
	go fmt.Fprintf(c, "GET http://%s/ HTTP/1.1\r\nHost: %[1]s\r\n\r\n", addr)

	if got := status(t, c); got != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", got)
	}
}

func TestPlainHTTPNeedsAbsoluteURL(t *testing.T) {
	c := serve([]string{"example.com"})
	defer c.Close()
	go fmt.Fprint(c, "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n")

	if got := status(t, c); got != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", got)
	}
}

// A client that hangs up part-way through its headers must not hang the proxy.
func TestHangupMidHeadersClosesConnection(t *testing.T) {
	c := serve([]string{"example.com"})
	go func() {
		fmt.Fprint(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n")
		c.Close()
	}()
	// Server side returns and closes its end; reading to EOF proves it did.
	io.Copy(io.Discard, c)
}
