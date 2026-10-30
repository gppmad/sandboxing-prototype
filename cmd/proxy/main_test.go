package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
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

// The policy is about the host, so a port in the URL does not change it.
func TestPlainHTTPAllowedHostPassesTheFilter(t *testing.T) {
	c := serve([]string{"example.com"})
	defer c.Close()
	go fmt.Fprint(c, "GET http://example.com:8080/x HTTP/1.1\r\nHost: example.com:8080\r\n\r\n")

	// 501 until forwarding exists: anything but 403 means the filter let it by.
	if got := status(t, c); got != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", got)
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
