package main

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

// readConnect takes a *bufio.Reader, so these need no sockets and no network —
// a strings.Reader is a whole client.
func reader(s string) *bufio.Reader { return bufio.NewReader(strings.NewReader(s)) }

func TestReadConnectReturnsTarget(t *testing.T) {
	r := reader("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")

	target, err := readConnect(r)
	if err != nil {
		t.Fatalf("readConnect: %v", err)
	}
	if target != "example.com:443" {
		t.Errorf("target = %q, want %q", target, "example.com:443")
	}
}

// The property the whole leak bug came down to: when readConnect returns, the
// reader must sit on the first byte of tunnel payload — not on a header line.
func TestReadConnectStopsAtTheBlankLine(t *testing.T) {
	const payload = "\x16\x03\x01 pretend this is a TLS ClientHello"
	r := reader("CONNECT example.com:443 HTTP/1.1\r\n" +
		"Host: example.com:443\r\n" +
		"Proxy-Connection: Keep-Alive\r\n" +
		"User-Agent: curl/8.4.0\r\n" +
		"\r\n" +
		payload)

	if _, err := readConnect(r); err != nil {
		t.Fatalf("readConnect: %v", err)
	}

	rest, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read rest: %v", err)
	}
	if string(rest) != payload {
		t.Errorf("reader left at %q, want it left at %q", string(rest), payload)
	}
}

func TestReadConnectRejectsOtherMethods(t *testing.T) {
	// A plain HTTP proxy request, which this proxy does not serve (see #20).
	r := reader("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")

	if _, err := readConnect(r); err == nil {
		t.Error("readConnect accepted a GET; want an error")
	}
}

func TestReadConnectRejectsMalformedRequestLine(t *testing.T) {
	// Two fields where the spec wants three.
	r := reader("CONNECT example.com:443\r\n\r\n")

	if _, err := readConnect(r); err == nil {
		t.Error("readConnect accepted a two-field request line; want an error")
	}
}

// A client that hangs up part-way through its headers never sends the blank
// line. readConnect has to give up on EOF rather than spin.
func TestReadConnectFailsOnHangupMidHeaders(t *testing.T) {
	r := reader("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n")

	if _, err := readConnect(r); err == nil {
		t.Error("readConnect returned success on a truncated request; want an error")
	}
}
