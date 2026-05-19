package remediate

import (
	"strings"
	"testing"
)

// FuzzSlugify asserts that slugify never panics and always produces a
// branch- and path-safe string. Output is constrained to lowercase
// alphanumerics and dashes, with no leading/trailing dashes and a length
// cap. The goal is to prevent a malicious finding title from breaking
// branch creation or producing an invalid path.
func FuzzSlugify(f *testing.F) {
	seeds := []string{
		"",
		"hello",
		"Hello World",
		"  spaces  ",
		"slash/in/middle",
		"...dots...",
		"emoji 🚀 finding",
		strings.Repeat("a", 200),
		"\x00\x01control",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got := slugify(in)
		if got == "" {
			t.Errorf("slugify(%q) returned empty string", in)
		}
		if len(got) > 60 {
			t.Errorf("slugify(%q) too long: %d chars", in, len(got))
		}
		if strings.HasPrefix(got, "-") || strings.HasSuffix(got, "-") {
			t.Errorf("slugify(%q) = %q has leading/trailing dash", in, got)
		}
		for _, r := range got {
			ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-'
			if !ok {
				t.Errorf("slugify(%q) = %q contains invalid rune %q", in, got, r)
				break
			}
		}
	})
}
