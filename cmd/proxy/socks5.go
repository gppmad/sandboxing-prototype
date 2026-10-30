package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strconv"

	"github.com/gppmad/sandboxing-prototype/internal/relay"
)

// The few pieces of SOCKS5 (RFC 1928) this proxy speaks. Only the CONNECT
// command is supported. The destination may be a domain name, which is what a
// client sends when it is told socks5h:// — the name goes to the proxy, which
// resolves it — or an IP address. A plain socks5:// client resolves a name
// itself, and the sandbox has no DNS for it to do that, so it has nothing to
// send.
const (
	socksVersion = 0x05

	methodNoAuth       = 0x00
	methodNoAcceptable = 0xFF

	cmdConnect = 0x01

	addrIPv4   = 0x01
	addrDomain = 0x03
	addrIPv6   = 0x04

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
	host, port, err := readSocksAddr(r, req[3])
	if errors.Is(err, errAddrType) {
		log.Printf("[socks5] address type %d -> REFUSED", req[3])
		socksReply(client, replyAddrNotSupported)
		return
	}
	if err != nil {
		log.Printf("[socks5] read address: %v", err)
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))

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

var errAddrType = errors.New("unknown address type")

// readSocksAddr reads the destination of a request: an address of the given
// type, then a two-byte port. The address comes back as text, the form the
// allowlist is written in: a domain name as sent, an IP in its usual notation.
func readSocksAddr(r io.Reader, atyp byte) (host string, port int, err error) {
	var addr []byte
	switch atyp {
	case addrIPv4:
		addr = make([]byte, 4)
	case addrIPv6:
		addr = make([]byte, 16)
	case addrDomain:
		// A domain is one length byte, then the name.
		size := make([]byte, 1)
		if _, err := io.ReadFull(r, size); err != nil {
			return "", 0, err
		}
		addr = make([]byte, size[0])
	default:
		return "", 0, errAddrType
	}
	if _, err := io.ReadFull(r, addr); err != nil {
		return "", 0, err
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, portBytes); err != nil {
		return "", 0, err
	}
	port = int(binary.BigEndian.Uint16(portBytes))

	if atyp == addrDomain {
		return string(addr), port, nil
	}
	return net.IP(addr).String(), port, nil
}
