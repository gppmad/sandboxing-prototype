// Command unix2tcp is the far side of the bridge: it listens on a Unix socket
// and dials out to a real TCP target for every connection that arrives there.
package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"

	"github.com/gppmad/sandboxing-prototype/internal/relay"
)

const (
	// socketPath is where this program listens. It is the same path
	// cmd/tcp2unix dials, which is what lets the two chain together.
	socketPath = "/tmp/x.sock"

	// targetAddr is the filtering proxy, not a website: this bridge hands
	// whatever arrives on the socket to the thing that decides where it may
	// actually go.
	targetAddr = "localhost:8080"
)

func main() {
	// A Unix socket file outlives the process that created it, so a previous
	// run leaves a path that Listen refuses with "address already in use" even
	// though nothing holds it. Clearing it first is what makes restarts work.
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Fatalf("remove stale socket: %v", err)
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	fmt.Printf("listening on %s, forwarding to %s\n", socketPath, targetAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			// One failed accept shouldn't kill the server.
			log.Printf("accept error: %v", err)
			continue
		}
		// One goroutine per connection so clients don't block each other.
		go handleConn(conn, targetAddr)
	}
}

// handleConn relays traffic between a socket client and the TCP target, so the
// client is transparently talking to whatever is on the other end.
func handleConn(client net.Conn, addr string) {
	defer client.Close()

	target, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("dial %s: %v", addr, err)
		return
	}
	defer target.Close()

	// Returns once either direction ends; the deferred Closes above then
	// unblock the copy still waiting on a Read.
	relay.Pipe(client, target)
}
