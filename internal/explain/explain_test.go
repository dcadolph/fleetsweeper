package explain

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// TestLookup verifies key, alias, case-insensitive, substring, and miss resolution.
func TestLookup(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In      string
		WantKey string
	}{{ // Test 0: Exact key.
		In: "node-health", WantKey: "node-health",
	}, { // Test 1: Alias.
		In: "memory-pressure", WantKey: "node-health",
	}, { // Test 2: Case-insensitive key.
		In: "Node-Health", WantKey: "node-health",
	}, { // Test 3: Substring on title.
		In: "Standards", WantKey: "security",
	}, { // Test 4: Unknown key.
		In: "nonexistent-topic-zzz", WantKey: "",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			gotKey := ""
			if got := Lookup(test.In); got != nil {
				gotKey = got.Key
			}
			if diff := cmp.Diff(test.WantKey, gotKey); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestKeys_Sorted verifies Keys returns every key in order.
func TestKeys_Sorted(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WantSorted bool
	}{{ // Test 0: Keys are sorted.
		WantSorted: true,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			k := Keys()
			sorted := true
			for i := 1; i < len(k); i++ {
				if k[i-1] > k[i] {
					sorted = false
				}
			}
			if diff := cmp.Diff(test.WantSorted, sorted); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(len(topics()), len(k)); diff != "" {
				t.Errorf("key count mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestRelated_Resolve verifies every Related entry resolves by exact key or alias.
func TestRelated_Resolve(t *testing.T) {
	t.Parallel()
	idx := indexByKey()
	type tc struct {
		Topic   string
		Related string
	}
	var tests []tc
	for _, tp := range topics() {
		for _, r := range tp.Related {
			tests = append(tests, tc{Topic: tp.Key, Related: r})
		}
	}
	if len(tests) == 0 {
		t.Fatal("no related entries found")
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s -> %s", testNum, test.Topic, test.Related), func(t *testing.T) {
			t.Parallel()
			_, ok := idx[strings.ToLower(test.Related)]
			if diff := cmp.Diff(true, ok); diff != "" {
				t.Errorf("related %q of %q does not resolve (-want +got):\n%s",
					test.Related, test.Topic, diff)
			}
		})
	}
}

// TestRender verifies section output and ANSI handling.
func TestRender(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In           string
		Color        bool
		WantContains []string
		WantANSI     bool
	}{{ // Test 0: Plain render includes every section.
		In: "fleet-score", Color: false, WantANSI: false,
		WantContains: []string{
			"Fleet Score", "Summary:", "Severity:", "How computed:",
			"Remediation:", "Probes:", "Related:",
		},
	}, { // Test 1: Colored render has ANSI codes.
		In: "rbac-audit", Color: true, WantANSI: true,
		WantContains: []string{"RBAC"},
	}, { // Test 2: Plain render has no ANSI codes.
		In: "rbac-audit", Color: false, WantANSI: false,
		WantContains: []string{"RBAC"},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			tp := Lookup(test.In)
			if tp == nil {
				t.Fatalf("%s topic missing", test.In)
			}
			out := Render(*tp, test.Color)
			var missing []string
			for _, want := range test.WantContains {
				if !strings.Contains(out, want) {
					missing = append(missing, want)
				}
			}
			if diff := cmp.Diff([]string(nil), missing, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("missing sections (-want +got):\n%s\n---\n%s", diff, out)
			}
			if diff := cmp.Diff(test.WantANSI, strings.Contains(out, "\033[")); diff != "" {
				t.Errorf("ANSI mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
