package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"

	"github.com/gppmad/sandboxing-prototype/internal/relay"
)

// The few pieces of SOCKS5 (RFC 1928) this proxy speaks. Only the CONNECT
// command with a domain name is supported, which is what a client sends when
// it is told socks5h:// — the name goes to the proxy, which resolves it. A
// plain socks5:// client resolves the name itself, and the sandbox has no DNS
// for it to do that.
const (
	socksVersion = 0x05

	methodNoAuth       = 0x00
	methodNoAcceptable = 0xFF

	cmdConnect = 0x01

	addrDomain = 0x03

	replySucceeded           = 0x00
	replyNotAllowed          = 0x02 // "connection not allowed by ruleset"
	replyHostUnreachable     = 0x04
	replyCommandNotSupported = 0x07
	replyAddrNotSupported    = 0x08
)

// handleSocks5 tunnels a client to the host it named in its SOCKS5 request, if
// that host is in the allowlist. r is the reader that already holds the
// client's first byte.
func handleSocks5(client net.Conn, r *bufio.Reader, allowlist []string) {
	// Greeting: version, how many auth methods, then the methods. There is no
	// authentication here — the proxy only listens on loopback — so method 0
	// has to be on offer.
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		log.Printf("[socks5] read greeting: %v", err)
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(r, methods); err != nil {
		log.Printf("[socks5] read methods: %v", err)
		return
	}
	if !bytes.Contains(methods, []byte{methodNoAuth}) {
		client.Write([]byte{socksVersion, methodNoAcceptable})
		return
	}
	client.Write([]byte{socksVersion, methodNoAuth})

	// Request: version, command, reserved, address type.
	req := make([]byte, 4)
	if _, err := io.ReadFull(r, req); err != nil {
		log.Printf("[socks5] read request: %v", err)
		return
	}
	if req[1] != cmdConnect {
		log.Printf("[socks5] command %d -> REFUSED (only CONNECT)", req[1])
		socksReply(client, replyCommandNotSupported)
		return
	}
	if req[3] != addrDomain {
		log.Printf("[socks5] address type %d -> REFUSED (only domain names)", req[3])
		socksReply(client, replyAddrNotSupported)
		return
	}

	// A domain address is one length byte, the name, then a two-byte port.
	size := make([]byte, 1)
	if _, err := io.ReadFull(r, size); err != nil {
		log.Printf("[socks5] read address: %v", err)
		return
	}
	rest := make([]byte, int(size[0])+2)
	if _, err := io.ReadFull(r, rest); err != nil {
		log.Printf("[socks5] read address: %v", err)
		return
	}
	host := string(rest[:size[0]])
	port := binary.BigEndian.Uint16(rest[size[0]:])
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	// Same rule as everywhere else, and before anything is dialed.
	if !allowed(host, allowlist) {
		log.Printf("[socks5] CONNECT %s -> REFUSED", target)
		socksReply(client, replyNotAllowed)
		return
	}

	log.Printf("[socks5] CONNECT %s -> ALLOWED", target)

	upstream, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("[socks5] dial %s: %v", target, err)
		socksReply(client, replyHostUnreachable)
		return
	}
	defer upstream.Close()

	if !socksReply(client, replySucceeded) {
		return
	}

	log.Printf("[socks5] tunnel established")
	relay.Pipe(client, upstream)
}

// socksReply answers a request with the given code and reports whether the
// write worked. The address that follows the code is the one the proxy dialed
// from; clients ignore it, so it is left as 0.0.0.0:0.
func socksReply(client net.Conn, code byte) bool {
	_, err := client.Write([]byte{socksVersion, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err == nil
}
