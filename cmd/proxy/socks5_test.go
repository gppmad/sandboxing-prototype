package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

// socksHello sends the greeting offering "no authentication" and checks the
// proxy accepts it.
func socksHello(t *testing.T, c net.Conn) {
	t.Helper()
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, []byte{0x05, 0x00}) {
		t.Fatalf("greeting reply = %v, %v; want 05 00", got, err)
	}
}

// socksRequest sends a request for cmd with the given address type and
// address bytes, and returns the reply code.
func socksRequest(t *testing.T, c net.Conn, cmd, atyp byte, addr []byte) byte {
	t.Helper()
	req := append([]byte{0x05, cmd, 0x00, atyp}, addr...)
	if _, err := c.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return reply[1]
}

// domainAddr encodes host:port the way a socks5h client sends it: a length
// byte, the name, a two-byte port.
func domainAddr(host string, port int) []byte {
	b := append([]byte{byte(len(host))}, host...)
	return binary.BigEndian.AppendUint16(b, uint16(port))
}

func TestSocks5RelaysToAllowedHost(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		io.ReadFull(c, buf)
		c.Write(bytes.ToUpper(buf))
	}()

	c := serve([]string{"localhost"})
	defer c.Close()
	socksHello(t, c)
	port := backend.Addr().(*net.TCPAddr).Port
	if code := socksRequest(t, c, 0x01, 0x03, domainAddr("localhost", port)); code != 0x00 {
		t.Fatalf("reply code = %d, want 0 (succeeded)", code)
	}

	c.Write([]byte("ping"))
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "PING" {
		t.Errorf("through the tunnel got %q, %v; want PING", got, err)
	}
}

func TestSocks5RefusesHostNotInAllowlist(t *testing.T) {
	c := serve([]string{"example.com"})
	defer c.Close()
	socksHello(t, c)

	if code := socksRequest(t, c, 0x01, 0x03, domainAddr("evil.com", 443)); code != 0x02 {
		t.Errorf("reply code = %d, want 2 (not allowed)", code)
	}
}

// With an empty allowlist everything is refused (default deny).
func TestSocks5RefusesEverythingWithEmptyAllowlist(t *testing.T) {
	c := serve(nil)
	defer c.Close()
	socksHello(t, c)

	if code := socksRequest(t, c, 0x01, 0x03, domainAddr("example.com", 443)); code != 0x02 {
		t.Errorf("reply code = %d, want 2 (not allowed)", code)
	}
}

// BIND and UDP ASSOCIATE are out of scope.
func TestSocks5RefusesOtherCommands(t *testing.T) {
	for _, cmd := range []byte{0x02, 0x03} {
		c := serve([]string{"example.com"})
		socksHello(t, c)
		if code := socksRequest(t, c, cmd, 0x03, domainAddr("example.com", 443)); code != 0x07 {
			t.Errorf("command %d: reply code = %d, want 7 (command not supported)", cmd, code)
		}
		c.Close()
	}
}

// IP addresses are not supported yet: IPv4 (1) and IPv6 (4).
func TestSocks5RefusesIPAddresses(t *testing.T) {
	for _, tc := range []struct {
		atyp byte
		addr []byte
	}{
		{0x01, []byte{127, 0, 0, 1, 0x01, 0xBB}},
		{0x04, append(make([]byte, 16), 0x01, 0xBB)},
	} {
		c := serve([]string{"127.0.0.1"})
		socksHello(t, c)
		if code := socksRequest(t, c, 0x01, tc.atyp, tc.addr); code != 0x08 {
			t.Errorf("address type %d: reply code = %d, want 8 (address type not supported)", tc.atyp, code)
		}
		c.Close()
	}
}

func TestSocks5NeedsNoAuthMethod(t *testing.T) {
	c := serve([]string{"example.com"})
	defer c.Close()

	// Offers only username/password (method 2).
	c.Write([]byte{0x05, 0x01, 0x02})
	got := make([]byte, 2)
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, []byte{0x05, 0xFF}) {
		t.Errorf("reply = %v, %v; want 05 FF (no acceptable method)", got, err)
	}
}

func TestSocks5UnreachableHost(t *testing.T) {
	// Take a free port, then close it so nothing is listening there.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	c := serve([]string{"localhost"})
	defer c.Close()
	socksHello(t, c)

	if code := socksRequest(t, c, 0x01, 0x03, domainAddr("localhost", port)); code != 0x04 {
		t.Errorf("reply code = %d, want 4 (host unreachable)", code)
	}
}
