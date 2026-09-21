// Command proxy is a CONNECT proxy: it reads the destination an HTTPS client
// names in cleartext, dials it, and then shuffles encrypted bytes between the
// two without ever taking part in the TLS handshake.
package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/gppmad/sandboxing-prototype/internal/relay"
)

func main() {
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	fmt.Println("listening on :8080")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConn(conn)
	}
}

// readConnect reads one CONNECT request off r and returns the host:port it
// names. It consumes the request line and every header line after it, leaving
// r positioned exactly at the first byte of tunnel payload — which is what
// keeps proxy headers from being relayed to a target expecting a handshake.
func readConnect(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read request line: %w", err)
	}

	// "CONNECT host:port HTTP/1.1" — the target is the middle field.
	fields := strings.Fields(strings.TrimRight(line, "\r\n"))
	if len(fields) != 3 || fields[0] != "CONNECT" {
		return "", fmt.Errorf("not a CONNECT request: %q", strings.TrimRight(line, "\r\n"))
	}

	// The headers after the request line — Host, Proxy-Connection and friends
	// — are addressed to this proxy and end at a blank line. Consuming them is
	// what moves r past the HTTP part of the stream.
	for {
		header, err := r.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("drain headers: %w", err)
		}
		if strings.TrimRight(header, "\r\n") == "" {
			break // the blank line: the request ends, the tunnel payload begins
		}
	}

	return fields[1], nil
}

// handleConn tunnels a client to whatever host it named in its CONNECT line.
// Nothing here decrypts anything: once the tunnel is open this is the same
// byte relay as the bridges, and the TLS handshake happens end to end between
// the client and the real server.
func handleConn(client net.Conn) {
	defer client.Close()

	// The reader is kept rather than discarded: bufio pulls a whole chunk off
	// the socket, so header lines the client sent after the request line are
	// already sitting in this buffer, not in the connection.
	r := bufio.NewReader(client)

	target, err := readConnect(r)
	if err != nil {
		log.Print(err)
		return
	}

	// The policy is about the host, not the port it was asked for.
	// SplitHostPort rather than strings.Split: an IPv6 literal is full of
	// colons and would not survive naive splitting.
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		log.Printf("malformed target %q: %v", target, err)
		return
	}

	// This check has to happen here, before the dial. Refusing a host after
	// connecting to it is not refusing it — the outbound connection already
	// happened.
	if !allowed(host) {
		log.Printf("refused: %s", host)
		fmt.Fprint(client, "HTTP/1.1 403 Forbidden\r\n\r\n")
		return
	}

	upstream, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("dial %s: %v", target, err)
		return
	}
	defer upstream.Close()

	// The signal the client is waiting for before it starts its handshake.
	if _, err := fmt.Fprint(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		log.Printf("write 200 to client: %v", err)
		return
	}

	log.Printf("tunnel open: %s", target)
	relay.Pipe(client, upstream)
}
