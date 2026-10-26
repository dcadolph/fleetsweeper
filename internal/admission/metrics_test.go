package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// TestNilMetrics verifies a nil Metrics ignores every call.
func TestNilMetrics(t *testing.T) {
	t.Parallel()
	var m *Metrics
	m.RecordDecision(ModeEnforce, DecisionDenied)
	m.RecordCheckFailure("digest-pin")
	var buf bytes.Buffer
	_, _ = m.WriteTo(&buf)
	if buf.Len() != 0 {
		t.Errorf("nil metrics wrote %q", buf.String())
	}
}

// TestMetricsWriteTo verifies the exposition output for recorded counters.
func TestMetricsWriteTo(t *testing.T) {
	t.Parallel()
	m := &Metrics{}
	m.RecordDecision(ModeEnforce, DecisionDenied)
	m.RecordDecision(ModeEnforce, DecisionDenied)
	m.RecordDecision(ModeAdvisory, DecisionWarned)
	m.RecordCheckFailure("digest-pin")
	var buf bytes.Buffer
	_, _ = m.WriteTo(&buf)
	out := buf.String()
	for _, want := range []string{
		"# TYPE fleetsweeper_admission_decisions_total counter",
		`fleetsweeper_admission_decisions_total{mode="enforce",decision="denied"} 2`,
		`fleetsweeper_admission_decisions_total{mode="advisory",decision="warned"} 1`,
		`fleetsweeper_admission_decisions_total{mode="advisory",decision="skipped"} 0`,
		"# TYPE fleetsweeper_admission_check_failures_total counter",
		`fleetsweeper_admission_check_failures_total{check="digest-pin"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// TestHandlerDryRunAndDecisions verifies the dry-run annotation and decision counting.
func TestHandlerDryRunAndDecisions(t *testing.T) {
	t.Parallel()
	dry := dirtyPod()
	dry.Annotations = map[string]string{DryRunAnnotation: "true"}
	notDry := dirtyPod()
	notDry.Annotations = map[string]string{DryRunAnnotation: "false"}
	pinned := NewPinnedBaselineProvider(sufficientBaseline).Current(context.Background())
	tests := []struct {
		Pod           corev1.Pod
		Baseline      Baseline
		Mode          Mode
		WantAllowed   bool
		WantDecision  string
		WantWouldDeny bool
	}{
		{ // Test 0: Dry-run pod is warned and never denied under enforce.
			Pod: dry, Baseline: pinned, Mode: ModeEnforce, WantAllowed: true,
			WantDecision: DecisionWarned, WantWouldDeny: true,
		},
		{ // Test 1: Same pod without dry-run is denied.
			Pod: notDry, Baseline: pinned, Mode: ModeEnforce, WantAllowed: false,
			WantDecision: DecisionDenied,
		},
		{ // Test 2: Clean pod is allowed.
			Pod: cleanPod(), Baseline: pinned, Mode: ModeEnforce, WantAllowed: true,
			WantDecision: DecisionAllowed,
		},
		{ // Test 3: Advisory mode with violations is warned.
			Pod: dirtyPod(), Baseline: pinned, Mode: ModeAdvisory, WantAllowed: true,
			WantDecision: DecisionWarned,
		},
		{ // Test 4: Insufficient baseline is skipped.
			Pod: dirtyPod(), Baseline: Baseline{}, Mode: ModeEnforce, WantAllowed: true,
			WantDecision: DecisionSkipped,
		},
	}
	for testNum, test := range tests {
		t.Run("test", func(t *testing.T) {
			t.Parallel()
			m := &Metrics{}
			h := NewHandler(fakeProvider{b: test.Baseline}, DefaultChecks(), test.Mode, zap.NewNop())
			h.Metrics = m
			raw, err := json.Marshal(test.Pod)
			if err != nil {
				t.Fatalf("marshal pod: %v", err)
			}
			resp := h.evaluate(context.Background(), &admissionv1.AdmissionRequest{
				UID: "u", Kind: metav1.GroupVersionKind{Kind: "Pod"}, Object: runtime.RawExtension{Raw: raw},
			})
			if resp.Allowed != test.WantAllowed {
				t.Errorf("test %d: allowed = %v, want %v", testNum, resp.Allowed, test.WantAllowed)
			}
			wouldDeny := false
			for _, w := range resp.Warnings {
				wouldDeny = wouldDeny || strings.Contains(w, "dry-run: would deny")
			}
			if wouldDeny != test.WantWouldDeny {
				t.Errorf("test %d: would-deny warning = %v, want %v", testNum, wouldDeny, test.WantWouldDeny)
			}
			var buf bytes.Buffer
			_, _ = m.WriteTo(&buf)
			want := `decision="` + test.WantDecision + `"} 1`
			if !strings.Contains(buf.String(), want) {
				t.Errorf("test %d: metrics missing %q:\n%s", testNum, want, buf.String())
			}
			wantFailures := test.WantDecision != DecisionSkipped && test.WantDecision != DecisionAllowed
			if diff := cmp.Diff(wantFailures,
				strings.Contains(buf.String(), "check_failures_total{")); diff != "" {
				t.Errorf("test %d: check failure counting mismatch (-want +got):\n%s", testNum, diff)
			}
		})
	}
}
