package main

import (
	"fmt"
	"io"
	"log"
	"net"
)

// targetAddr is the fixed destination every accepted connection is forwarded to.
const targetAddr = "example.com:80"

func main() {
	// The empty host in ":9001" binds all interfaces — 0.0.0.0 and [::].
	ln, err := net.Listen("tcp", ":9001")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	fmt.Printf("listening on :9001, forwarding to %s\n", targetAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			// One failed accept (e.g. too many open files) shouldn't kill
			// the server.
			log.Printf("accept error: %v", err)
			continue
		}
		// One goroutine per connection so clients don't block each other.
		go handleConn(conn, targetAddr)
	}
}

// handleConn relays traffic between client and addr, so the client is
// transparently talking to whatever is on the other end.
func handleConn(client net.Conn, addr string) {
	defer client.Close()

	target, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("dial %s: %v", addr, err)
		return
	}
	defer target.Close()

	// A connection is full-duplex — two independent streams — so relaying
	// it takes two copies running at once. Both report into the same
	// channel so we return as soon as either direction ends; the deferred
	// Closes then unblock the other copy's pending Read.
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(client, target) // target -> client
		done <- struct{}{}
	}()
	go func() {
		io.Copy(target, client) // client -> target
		done <- struct{}{}
	}()

	<-done
}
