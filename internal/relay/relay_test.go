package relay

import (
	"io"
	"net"
	"testing"
	"time"
)

// Pipe takes io.ReadWriteCloser, so this uses net.Pipe() — in-memory
// connections with no sockets, no ports, and no network.

// TestPipeRelaysBothDirections is the property that matters: bytes written by
// either peer come out at the other one.
func TestPipeRelaysBothDirections(t *testing.T) {
	// clientEnd <-> a is one connection; b <-> targetEnd is the other.
	// Pipe(a, b) joins them, so clientEnd and targetEnd can talk.
	clientEnd, a := net.Pipe()
	b, targetEnd := net.Pipe()
	defer clientEnd.Close()
	defer targetEnd.Close()

	go Pipe(a, b)

	// client -> target
	if _, err := clientEnd.Write([]byte("ping")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if got := read(t, targetEnd, 4); got != "ping" {
		t.Errorf("target received %q, want %q", got, "ping")
	}

	// target -> client, on the same pair of connections
	if _, err := targetEnd.Write([]byte("pong")); err != nil {
		t.Fatalf("target write: %v", err)
	}
	if got := read(t, clientEnd, 4); got != "pong" {
		t.Errorf("client received %q, want %q", got, "pong")
	}
}

// TestPipeReturnsWhenOneSideCloses covers the bug that showed up in the first
// version of the forwarder: waiting for a specific direction hangs when the
// other one finishes first. Pipe must return on whichever ends first.
func TestPipeReturnsWhenOneSideCloses(t *testing.T) {
	clientEnd, a := net.Pipe()
	b, targetEnd := net.Pipe()
	defer clientEnd.Close()

	returned := make(chan struct{})
	go func() {
		Pipe(a, b)
		close(returned)
	}()

	// net.Pipe is synchronous — a Write blocks until someone reads it — so the
	// client has to be draining for the target's reply to go anywhere. A real
	// client does the same thing: it reads the response it is waiting for.
	go io.Copy(io.Discard, clientEnd)

	// The target replies and hangs up while the client keeps its side open,
	// which is what an HTTP server sending "Connection: close" does.
	targetEnd.Write([]byte("bye"))
	targetEnd.Close()

	select {
	case <-returned:
		// Pipe noticed the target-side EOF and returned. Correct.
	case <-time.After(2 * time.Second):
		t.Fatal("Pipe did not return after one side closed — it is waiting on the wrong direction")
	}
}

func read(t *testing.T, c net.Conn, n int) string {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(buf)
}
