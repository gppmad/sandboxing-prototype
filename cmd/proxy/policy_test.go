package main

import "testing"

func TestAllowed(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"example.com", true},

		// Everything else is refused, including hosts that merely look
		// related. The match is exact until D2 brings real list semantics.
		{"wikipedia.org", false},
		{"www.example.com", false},
		{"example.com.evil.test", false}, // suffix trick: must not match
		{"notexample.com", false},        // prefix trick: must not match
		{"", false},
	}

	for _, c := range cases {
		if got := allowed(c.host); got != c.want {
			t.Errorf("allowed(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}
