package imageaudit

import (
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
)

// FuzzParseImageRef asserts the package's image-reference parsers never panic
// on arbitrary strings and that their outputs stay well formed. isLatestOrNoTag
// must flag any digest-stripped ref ending in ":latest", normalizeServer must
// never leave a recognized scheme prefix behind, and any reference that
// name.ParseReference accepts must expose non-empty registry and name fields.
func FuzzParseImageRef(f *testing.F) {
	seeds := []string{
		"",
		"nginx",
		"nginx:1.27",
		"nginx:latest",
		"registry.example.com:5000/team/app:v1",
		"gcr.io/proj/img@sha256:" + strings.Repeat("a", 64),
		"docker.io/library/busybox",
		"localhost:5000/x",
		"UPPER/Case:Tag",
		"https://index.docker.io/v1/",
		":::",
		"@@@",
		"a/b/c/d/e:f@g",
		"\x00\x01\x02",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, ref string) {
		// isLatestOrNoTag must be crash-safe and honor its contract: a ref
		// whose digest-stripped form ends in ":latest" is always flagged.
		flagged := isLatestOrNoTag(ref)
		base := ref
		if i := strings.Index(base, "@"); i >= 0 {
			base = base[:i]
		}
		if strings.HasSuffix(base, ":latest") && !flagged {
			t.Errorf("isLatestOrNoTag(%q) = false but tag is :latest", ref)
		}

		// normalizeServer must strip any scheme it recognizes.
		if got := normalizeServer(ref); strings.HasPrefix(got, "https://") ||
			strings.HasPrefix(got, "http://") {
			t.Errorf("normalizeServer(%q) left a scheme prefix: %q", ref, got)
		}

		// The full parser probeOne relies on: only assert on success, since
		// most random strings are legitimately invalid references.
		parsed, err := name.ParseReference(ref)
		if err != nil {
			return
		}
		if parsed.Name() == "" {
			t.Errorf("name.ParseReference(%q) produced an empty Name", ref)
		}
		if parsed.Context().RegistryStr() == "" {
			t.Errorf("name.ParseReference(%q) produced an empty registry", ref)
		}
	})
}
