package main

import (
	"fmt"
	"io"
	"log"
	"net"
)

func main() {
	// Ask the OS for a TCP listener bound to all interfaces on port 9001.
	// ":9001" means ":<port>" — the empty host binds to 0.0.0.0 (IPv4) and [::] (IPv6).
	ln, err := net.Listen("tcp", ":9001")
	if err != nil {
		// log.Fatalf prints the error and exits the process (non-zero status).
		// We can't run a server if we can't listen, so this is fatal.
		log.Fatalf("failed to listen: %v", err)
	}
	// Ensure the listener is closed when main returns. Even though the
	// accept loop below runs forever, this keeps things tidy if we ever
	// add a shutdown path later.
	defer ln.Close()

	fmt.Println("listening on :9001")

	// The accept loop: block on ln.Accept() until a new client connects,
	// then hand that connection off to a goroutine and immediately loop
	// back to wait for the next one. This is what keeps the server
	// running after a client disconnects — we never exit the loop.
	for {
		conn, err := ln.Accept()
		if err != nil {
			// A single accept failure (e.g. too many open files) shouldn't
			// kill the whole server. Log it and try again.
			log.Printf("accept error: %v", err)
			continue
		}
		// One goroutine per connection so many clients can be served
		// concurrently without blocking each other.
		go handleConn(conn)
	}
}

// handleConn reads everything the client sends and writes it straight back,
// which is exactly what an "echo" server does. It runs in its own goroutine.
func handleConn(conn net.Conn) {
	// Close the connection when we're done (i.e. when the client
	// disconnects and io.Copy returns). This signals EOF to the peer.
	defer conn.Close()

	// io.Copy(dst, src) copies from src to dst until src hits EOF.
	// Here dst and src are both conn, so every byte the client writes
	// is read and immediately written back on the same connection.
	// When the client closes its side, Read returns EOF, io.Copy
	// returns, and the deferred conn.Close() fires.
	if _, err := io.Copy(conn, conn); err != nil {
		log.Printf("echo error: %v", err)
	}
}
