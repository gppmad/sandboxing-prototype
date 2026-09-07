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

// handleConn tunnels a client to whatever host it named in its CONNECT line.
// Nothing here decrypts anything: once the tunnel is open this is the same
// byte relay as the bridges, and the TLS handshake happens end to end between
// the client and the real server.
func handleConn(client net.Conn) {
	defer client.Close()

	// The reader is kept rather than discarded: bufio pulls a whole chunk off
	// the socket, so any header lines the client sent after the request line
	// are already sitting in this buffer, not in the connection.
	r := bufio.NewReader(client)

	line, err := r.ReadString('\n')
	if err != nil {
		log.Printf("read request line: %v", err)
		return
	}

	// "CONNECT host:port HTTP/1.1" — the target is the middle field.
	fields := strings.Fields(strings.TrimRight(line, "\r\n"))
	if len(fields) != 3 || fields[0] != "CONNECT" {
		log.Printf("not a CONNECT request: %q", strings.TrimRight(line, "\r\n"))
		return
	}
	target := fields[1]

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
