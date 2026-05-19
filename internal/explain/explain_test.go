package explain

import (
	"strings"
	"testing"
)

func TestLookup_ExactKey(t *testing.T) {
	t.Parallel()
	tp := Lookup("node-health")
	if tp == nil {
		t.Fatalf("expected node-health topic; got nil")
	}
	if tp.Key != "node-health" {
		t.Errorf("key: want node-health, got %s", tp.Key)
	}
}

func TestLookup_Alias(t *testing.T) {
	t.Parallel()
	tp := Lookup("memory-pressure")
	if tp == nil || tp.Key != "node-health" {
		t.Errorf("alias memory-pressure should resolve to node-health; got %+v", tp)
	}
}

func TestLookup_CaseInsensitive(t *testing.T) {
	t.Parallel()
	tp := Lookup("Node-Health")
	if tp == nil {
		t.Errorf("expected case-insensitive lookup to hit")
	}
}

func TestLookup_Fallback(t *testing.T) {
	t.Parallel()
	// Substring on title should still resolve.
	tp := Lookup("Standards")
	if tp == nil || tp.Key != "security" {
		t.Errorf("substring 'Standards' should hit Pod Security Standards; got %+v", tp)
	}
}

func TestLookup_NotFound(t *testing.T) {
	t.Parallel()
	if Lookup("nonexistent-topic-zzz") != nil {
		t.Errorf("expected nil for unknown key")
	}
}

func TestKeys_Sorted(t *testing.T) {
	t.Parallel()
	k := Keys()
	for i := 1; i < len(k); i++ {
		if k[i-1] > k[i] {
			t.Errorf("keys not sorted at %d: %s > %s", i, k[i-1], k[i])
		}
	}
}

func TestRender_IncludesAllSections(t *testing.T) {
	t.Parallel()
	tp := Lookup("fleet-score")
	if tp == nil {
		t.Fatalf("fleet-score topic missing")
	}
	out := Render(*tp, false)
	for _, want := range []string{
		"Fleet Score", "Summary:", "Severity:", "How computed:",
		"Remediation:", "Probes:", "Related:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered output missing section %q\n---\n%s", want, out)
		}
	}
}

func TestRender_ColorWrappers(t *testing.T) {
	t.Parallel()
	tp := *Lookup("rbac-audit")
	plain := Render(tp, false)
	colored := Render(tp, true)
	if strings.Contains(plain, "\033[") {
		t.Errorf("plain render should not contain ANSI codes")
	}
	if !strings.Contains(colored, "\033[") {
		t.Errorf("colored render should contain ANSI codes")
	}
}
