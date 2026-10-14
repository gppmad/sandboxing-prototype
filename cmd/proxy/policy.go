package main

import "slices"

// allowed reports whether a CONNECT may proceed to host: only if host is in
// the allowlist. The match is exact, so "www.example.com" needs its own
// entry, and an empty list refuses everything (default deny).
func allowed(host string, allowlist []string) bool {
	return slices.Contains(allowlist, host)
}
