// Package relay wires two connections together and copies bytes between them.
package relay

import "io"

// Pipe relays bytes between a and b in both directions and returns as soon as
// either direction ends. It does not close a or b — that is the caller's job,
// and it is what unblocks the copy still waiting on a Read.
//
// The parameters are io.ReadWriteCloser rather than net.Conn so this works for
// anything with the same shape: TCP connections, Unix sockets, net.Pipe in
// tests.
func Pipe(a, b io.ReadWriteCloser) {
	// A connection is full-duplex — two independent streams — so relaying it
	// takes two copies running at once. Both report into the same channel so
	// we return on the first one to finish: one peer may close after replying
	// while the other holds its side open, so waiting for a specific
	// direction can hang.
	//
	// The channel is buffered because only one value is ever received. The
	// second copy still sends when it finishes, and without a free slot that
	// goroutine would park forever on a send nobody will receive.
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(a, b) // b -> a
		done <- struct{}{}
	}()
	go func() {
		io.Copy(b, a) // a -> b
		done <- struct{}{}
	}()

	<-done
}
