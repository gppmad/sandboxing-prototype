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

// echoBackend listens on network/addr, upper-cases the first four bytes it
// receives and sends them back. It returns the listener.
func echoBackend(t *testing.T, network, addr string) net.Listener {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		io.ReadFull(c, buf)
		c.Write(bytes.ToUpper(buf))
	}()
	return ln
}

// ipAddr encodes ip:port the way a client sends an IPv4 or IPv6 destination:
// the raw address bytes, then a two-byte port.
func ipAddr(ip net.IP, port int) (atyp byte, addr []byte) {
	if v4 := ip.To4(); v4 != nil {
		return 0x01, binary.BigEndian.AppendUint16(v4, uint16(port))
	}
	return 0x04, binary.BigEndian.AppendUint16(ip.To16(), uint16(port))
}

// The allowlist holds the IP as text, the same as it does for HTTP and HTTPS.
func TestSocks5RelaysToAllowedIP(t *testing.T) {
	for _, tc := range []struct{ name, network, host string }{
		{"IPv4", "tcp4", "127.0.0.1"},
		{"IPv6", "tcp6", "::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln := echoBackend(t, tc.network, net.JoinHostPort(tc.host, "0"))
			defer ln.Close()

			c := serve([]string{tc.host})
			defer c.Close()
			socksHello(t, c)
			atyp, addr := ipAddr(net.ParseIP(tc.host), ln.Addr().(*net.TCPAddr).Port)
			if code := socksRequest(t, c, 0x01, atyp, addr); code != 0x00 {
				t.Fatalf("reply code = %d, want 0 (succeeded)", code)
			}

			c.Write([]byte("ping"))
			got := make([]byte, 4)
			if _, err := io.ReadFull(c, got); err != nil || string(got) != "PING" {
				t.Errorf("through the tunnel got %q, %v; want PING", got, err)
			}
		})
	}
}

func TestSocks5RefusesIPNotInAllowlist(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1"} {
		// example.com being allowed says nothing about an IP: the policy
		// compares the text it is given, it does not resolve names.
		c := serve([]string{"example.com"})
		socksHello(t, c)
		atyp, addr := ipAddr(net.ParseIP(ip), 443)
		if code := socksRequest(t, c, 0x01, atyp, addr); code != 0x02 {
			t.Errorf("%s: reply code = %d, want 2 (not allowed)", ip, code)
		}
		c.Close()
	}
}

func TestSocks5RefusesUnknownAddressType(t *testing.T) {
	c := serve([]string{"example.com"})
	defer c.Close()
	socksHello(t, c)

	if code := socksRequest(t, c, 0x01, 0x02, nil); code != 0x08 {
		t.Errorf("reply code = %d, want 8 (address type not supported)", code)
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
