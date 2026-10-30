//go:build linux

package main

import (
	"slices"
	"testing"
)

func TestExpandAllow(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{"one host",
			[]string{"--allow", "a.com", "--", "curl"},
			[]string{"--allow", "a.com", "--", "curl"}},
		{"several hosts",
			[]string{"--allow", "a.com", "b.com", "--", "npm", "install"},
			[]string{"--allow", "a.com", "--allow", "b.com", "--", "npm", "install"}},
		{"flag repeated, as before",
			[]string{"--allow", "a.com", "--allow", "b.com", "--", "curl"},
			[]string{"--allow", "a.com", "--allow", "b.com", "--", "curl"}},
		{"repeated, with lists",
			[]string{"--allow", "a.com", "b.com", "--allow", "c.com", "--", "curl"},
			[]string{"--allow", "a.com", "--allow", "b.com", "--allow", "c.com", "--", "curl"}},
		{"the command's own words are left alone",
			[]string{"--allow", "a.com", "--", "curl", "-v", "b.com"},
			[]string{"--allow", "a.com", "--", "curl", "-v", "b.com"}},
		{"a later flag ends the list",
			[]string{"--allow", "a.com", "-h", "b.com", "--", "curl"},
			[]string{"--allow", "a.com", "-h", "b.com", "--", "curl"}},
		{"no -- : unchanged, so the command is not read as a host",
			[]string{"--allow", "a.com", "curl", "https://a.com"},
			[]string{"--allow", "a.com", "curl", "https://a.com"}},
		{"no --allow",
			[]string{"--", "curl"},
			[]string{"--", "curl"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := expandAllow(tc.args); !slices.Equal(got, tc.want) {
				t.Errorf("expandAllow(%q) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}
