package main

import "testing"

func TestAllowed(t *testing.T) {
	allowlist := []string{"example.com", "github.com"}

	cases := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"github.com", true},

		// Everything else is refused, including hosts that merely look
		// related. The match is exact.
		{"wikipedia.org", false},
		{"www.example.com", false},
		{"example.com.evil.test", false}, // suffix trick: must not match
		{"notexample.com", false},        // prefix trick: must not match
		{"", false},
	}

	for _, c := range cases {
		if got := allowed(c.host, allowlist); got != c.want {
			t.Errorf("allowed(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

// With no allowlist, nothing gets through.
func TestAllowedEmptyList(t *testing.T) {
	if allowed("example.com", nil) {
		t.Error("allowed(\"example.com\", nil) = true, want false")
	}
}
