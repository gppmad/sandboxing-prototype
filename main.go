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

// handleConn is where A2 diverges from A1. In A1 we echoed bytes back on the
// SAME connection (server side only). Here we forward them to a real target.
// It still runs in its own goroutine, one per accepted client.
func handleConn(client net.Conn) {
	// Close the client connection when we're done.
	defer client.Close()

	// ---- POINT 1: dial out (the CLIENT side of TCP) ----
	//
	// net.Dial is the active, client side of the handshake: WE reach out and
	// open a connection TO example.com:80. Contrast with main(), which uses
	// net.Listen + Accept — the passive, server side, where we wait for others
	// to reach out to US.
	//
	// So this one program now holds TWO sockets per connection:
	//   - `client`: we are the SERVER of it (it came in via Accept)
	//   - `target`: we are the CLIENT of it (we opened it via Dial)
	target, err := net.Dial("tcp", "example.com:80")
	if err != nil {
		// If we can't reach the target, this client can't be served. Log and
		// return; the deferred client.Close() drops the client connection.
		log.Printf("dial error: %v", err)
		return
	}
	// Close the target connection too when we're done.
	defer target.Close()

	// ---- Minimal relay so point 1 is testable RIGHT NOW ----
	//
	// This inline two-way copy is deliberately quick-and-dirty. Turning it into
	// a reusable, properly-synchronized `pipe(a, b io.ReadWriteCloser)` helper
	// is POINT 2 — not done here on purpose so we can see point 1 in isolation.
	//
	// One direction runs in a goroutine (client -> target); the other runs
	// inline (target -> client). When example.com finishes its HTTP/1.0
	// response it closes, io.Copy below returns, handleConn returns, and the
	// deferred Close() calls tear down both sockets — which unblocks the
	// goroutine's copy as well.
	go io.Copy(target, client) // client's request bytes -> target
	io.Copy(client, target)    // target's response bytes -> client
}
