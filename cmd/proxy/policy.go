package main

// allowedHost is the single destination this proxy will tunnel to. Everything
// else is refused. D2 replaces this with real allow and deny lists.
const allowedHost = "example.com"

// allowed reports whether a CONNECT may proceed to host. The match is exact,
// so "www.example.com" is refused along with everything else — subdomain
// handling comes with the lists.
func allowed(host string) bool {
	return host == allowedHost
}
