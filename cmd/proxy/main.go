// Command proxy is a filtering proxy. One port serves three kinds of client:
//
//   - CONNECT (HTTPS): it reads the destination the client names in cleartext,
//     dials it, and then shuffles encrypted bytes between the two without ever
//     taking part in the TLS handshake.
//   - plain HTTP (`GET http://host/path`): it reads the request, forwards it to
//     the host in the URL, and relays the response back.
//   - SOCKS5 (`socks5h://`): it reads the host name the client sends, dials it,
//     and relays bytes like a CONNECT tunnel.
//
// All of them go through the same allowlist, checked before anything is dialed.
//
// Usage: proxy <listen addr> [allowed host]...
//
//	proxy 127.0.0.1:8080 example.com github.com
//	      └─ listen addr ┘ └──── allowed hosts ────┘
//
// With no allowed hosts, it refuses everything.
package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/gppmad/sandboxing-prototype/internal/relay"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: proxy <listen addr> [allowed host]...")
		os.Exit(2)
	}
	// Pass a loopback address such as 127.0.0.1:8080. A bare ":8080" would
	// listen on every interface and make this an open proxy for the network.
	addr := os.Args[1]
	allowlist := os.Args[2:]

	// IPv4 only, to match cmd/tcp2unix — see the note there.
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	fmt.Printf("listening on %s, allowing %v\n", addr, allowlist)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConn(conn, allowlist)
	}
}

// handleConn reads one request off the client and dispatches on its method:
// CONNECT opens a tunnel, anything else is a plain HTTP proxy request.
func handleConn(client net.Conn, allowlist []string) {
	defer client.Close()

	// The reader is kept rather than discarded: bufio pulls a whole chunk off
	// the socket, so anything the client sent after the headers is already
	// sitting in this buffer, not in the connection.
	r := bufio.NewReader(client)

	// A SOCKS5 client opens with the version byte 0x05. No HTTP request can
	// start with it, so the first byte tells the two protocols apart and one
	// port serves both. Peek leaves the byte in r for whoever reads next.
	first, err := r.Peek(1)
	if err != nil {
		log.Printf("[proxy] read first byte: %v", err)
		return
	}
	if first[0] == socksVersion {
		handleSocks5(client, r, allowlist)
		return
	}

	// ReadRequest consumes the request line and every header up to the blank
	// line, leaving r at the first byte of whatever follows — for CONNECT,
	// the tunnel payload.
	req, err := http.ReadRequest(r)
	if err != nil {
		log.Printf("[proxy] read request: %v", err)
		return
	}

	if req.Method == http.MethodConnect {
		handleConnect(client, req.Host, allowlist)
		return
	}

	handleHTTP(client, req, allowlist)
}

// handleHTTP serves a plain HTTP proxy request (`GET http://host/path`) if the
// host in its URL is in the allowlist.
func handleHTTP(client net.Conn, req *http.Request, allowlist []string) {
	// A proxy request names its destination in the URL. `GET /` has no host in
	// it, so it is a request to this proxy itself, not through it.
	if !req.URL.IsAbs() {
		log.Printf("[proxy] %s %s -> BAD REQUEST (not an absolute URL)", req.Method, req.URL)
		fmt.Fprint(client, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}

	// Same rule as CONNECT, and again before anything is dialed.
	host := req.URL.Hostname()
	if !allowed(host, allowlist) {
		log.Printf("[proxy] %s %s -> REFUSED", req.Method, req.URL)
		fmt.Fprint(client, "HTTP/1.1 403 Forbidden\r\n\r\n")
		return
	}

	log.Printf("[proxy] %s %s -> ALLOWED", req.Method, req.URL)

	// The request came in proxy form (absolute URL, proxy headers). Make it the
	// request a server would expect: origin-form, and without anything that was
	// addressed to this proxy rather than to the destination.
	req.RequestURI = "" // RoundTrip refuses a request that still has one
	removeHopByHop(req.Header)

	resp, err := transport.RoundTrip(req)
	if err != nil {
		log.Printf("[proxy] forward %s: %v", req.URL, err)
		fmt.Fprint(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer resp.Body.Close()
	log.Printf("[proxy] %s %s -> upstream said %s", req.Method, req.URL, resp.Status)

	// Hand the response back the same way: without the upstream connection's
	// own headers, and closing after it since we serve one request per client
	// connection.
	removeHopByHop(resp.Header)
	resp.Close = true
	if err := resp.Write(client); err != nil {
		log.Printf("[proxy] write response to client: %v", err)
	}
}

// transport sends the forwarded requests. Its Proxy field is left nil on
// purpose: the default transport would honour HTTP_PROXY, which inside the
// sandbox points back at this proxy. Compression is off so the body reaches
// the client byte for byte instead of being decoded here.
var transport = &http.Transport{DisableCompression: true}

// hopByHop are the headers that describe one connection, not the message, so
// a proxy must not pass them on (RFC 9110 §7.6.1).
var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// removeHopByHop deletes the hop-by-hop headers from h, including any other
// header the client listed in its Connection header.
func removeHopByHop(h http.Header) {
	for _, v := range h["Connection"] {
		for name := range strings.SplitSeq(v, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range hopByHop {
		h.Del(name)
	}
}

// handleConnect tunnels a client to target (host:port) if the host is in the
// allowlist.
// Nothing here decrypts anything: once the tunnel is open this is the same
// byte relay as the bridges, and the TLS handshake happens end to end between
// the client and the real server.
func handleConnect(client net.Conn, target string, allowlist []string) {

	// The policy is about the host, not the port it was asked for.
	// SplitHostPort rather than strings.Split: an IPv6 literal is full of
	// colons and would not survive naive splitting.
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		log.Printf("[proxy] malformed target %q: %v", target, err)
		return
	}

	// This check has to happen here, before the dial. Refusing a host after
	// connecting to it is not refusing it — the outbound connection already
	// happened.
	if !allowed(host, allowlist) {
		log.Printf("[proxy] CONNECT %s -> REFUSED", target)
		fmt.Fprint(client, "HTTP/1.1 403 Forbidden\r\n\r\n")
		return
	}

	log.Printf("[proxy] CONNECT %s -> ALLOWED", target)

	upstream, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("[proxy] dial %s: %v", target, err)
		return
	}
	defer upstream.Close()

	// The signal the client is waiting for before it starts its handshake.
	if _, err := fmt.Fprint(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		log.Printf("[proxy] write 200 to client: %v", err)
		return
	}

	log.Printf("[proxy] tunnel established")
	relay.Pipe(client, upstream)
}
