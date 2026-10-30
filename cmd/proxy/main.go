// Command proxy is a CONNECT proxy: it reads the destination an HTTPS client
// names in cleartext, dials it, and then shuffles encrypted bytes between the
// two without ever taking part in the TLS handshake.
//
// It listens on the address in its first argument. The hosts it may tunnel
// to are the rest; with none, it refuses all:
//
//	proxy 127.0.0.1:8080 example.com github.com
package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

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

// respond writes a small plain-text response and tells the client we are done.
func respond(client net.Conn, code int, msg string) {
	fmt.Fprintf(client, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(msg), msg)
}

// handleHTTP serves a plain HTTP proxy request (`GET http://host/path`) if the
// host in its URL is in the allowlist.
func handleHTTP(client net.Conn, req *http.Request, allowlist []string) {
	// A proxy request names its destination in the URL. `GET /` has no host in
	// it, so it is a request to this proxy itself, not through it.
	if !req.URL.IsAbs() {
		log.Printf("[proxy] %s %s -> BAD REQUEST (not an absolute URL)", req.Method, req.URL)
		respond(client, http.StatusBadRequest, "proxy requests need an absolute URL\n")
		return
	}

	// Same rule as CONNECT, and again before anything is dialed.
	host := req.URL.Hostname()
	if !allowed(host, allowlist) {
		log.Printf("[proxy] %s %s -> REFUSED", req.Method, req.URL)
		respond(client, http.StatusForbidden, "host not allowed: "+host+"\n")
		return
	}

	log.Printf("[proxy] %s %s -> ALLOWED", req.Method, req.URL)

	// Forwarding comes in the next steps.
	respond(client, http.StatusNotImplemented, "forwarding plain HTTP is not implemented yet\n")
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
