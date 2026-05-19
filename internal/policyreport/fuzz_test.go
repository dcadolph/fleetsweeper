package policyreport

import (
	"strings"
	"testing"
)

// FuzzParseResourceRef asserts that parseResourceRef never panics on
// arbitrary Affected strings. The function is a forgiving fallback parser
// (used to populate ResourceRef on emitted PolicyReports) so the only
// real invariant is "no panic, no infinite loop". Values that look like
// "Kind ns/name", "ns/name", or random garbage all need to round-trip.
func FuzzParseResourceRef(f *testing.F) {
	seeds := []string{
		"",
		"   ",
		"Deployment kube-system/coredns",
		"kube-system/coredns",
		"/leading-slash",
		"trailing/",
		"Kind /no-name",
		"Kind ns/name extra",
		"\x00\x01\x02",
		"a/b/c/d/e",
		"😀/🚀",
		strings.Repeat("a/", 200),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		ref := parseResourceRef(in)
		// Trivial post-condition: every ref must have a non-empty Name
		// (the function uses "(unknown)" when input is blank).
		if ref.Name == "" {
			t.Errorf("parseResourceRef(%q) produced empty Name", in)
		}
	})
}
