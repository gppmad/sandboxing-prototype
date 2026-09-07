// Command proxy is the beginnings of a CONNECT proxy. For now it only reads
// the first line each client sends and prints it, to show that an HTTPS
// client names its destination in cleartext before any TLS handshake starts.
package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
)

func main() {
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	fmt.Println("listening on :8080")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConn(conn)
	}
}

// handleConn prints the first line the client sent and hangs up. Nothing is
// written back, so the client's request fails — the point here is only to
// show what arrives, and in what form.
func handleConn(client net.Conn) {
	defer client.Close()

	// HTTP is line-oriented, so a bufio.Reader is the natural way to take
	// exactly one line off the connection.
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		log.Printf("read first line: %v", err)
		return
	}

	// Lines arrive CRLF-terminated. Trimming both keeps the print clean —
	// a stray \r is invisible on screen but still there.
	fmt.Printf("%s\n", strings.TrimRight(line, "\r\n"))
}
