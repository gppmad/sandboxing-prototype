package main

import (
	"fmt"
	"log"
	"net"

	"github.com/gppmad/sandboxing-prototype/internal/relay"
)

// targetSocket is the Unix socket every accepted connection is bridged into.
// A Unix socket is addressed by a filesystem path, not host:port — which is
// what lets it cross into a process that has no network stack at all.
const targetSocket = "/tmp/x.sock"

func main() {
	// "tcp4" rather than "tcp": the wildcard listener would otherwise be
	// dual-stack, and clients try IPv6 first, so connections would arrive
	// from [::1] instead of 127.0.0.1. 3128 is Squid's default and the
	// conventional port for an HTTP proxy, which is what this bridge fronts.
	ln, err := net.Listen("tcp4", ":3128")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	fmt.Printf("listening on :3128, bridging into %s\n", targetSocket)

	for {
		conn, err := ln.Accept()
		if err != nil {
			// One failed accept (e.g. too many open files) shouldn't kill
			// the server.
			log.Printf("accept error: %v", err)
			continue
		}
		// One goroutine per connection so clients don't block each other.
		go handleConn(conn, targetSocket)
	}
}

// handleConn relays traffic between client and the Unix socket at path, so
// the client is transparently talking to whatever is listening there.
func handleConn(client net.Conn, path string) {
	defer client.Close()

	log.Printf("[tcp2unix] accepted client from %s", client.RemoteAddr())
	log.Printf("[tcp2unix] dialing socket %s", path)

	// Only the network changes from the TCP forwarder — relay.Pipe takes
	// io.ReadWriteCloser, so it does not care which one this is.
	// A missing socket file fails here with "no such file or directory",
	// not the "connection refused" a dead TCP port gives you.
	target, err := net.Dial("unix", path)
	if err != nil {
		log.Printf("dial %s: %v", path, err)
		return
	}
	defer target.Close()

	// Returns once either direction ends; the deferred Closes above then
	// unblock the copy still waiting on a Read.
	relay.Pipe(client, target)
}
