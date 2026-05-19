package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dcadolph/fleetsweeper/internal/admission"
)

// TestEvaluatePod_NoDriftAtThinBaseline verifies a pod with risky
// settings produces no findings when the baseline is below the
// 70% activation threshold for every check.
func TestEvaluatePod_NoDriftAtThinBaseline(t *testing.T) {
	t.Parallel()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
		Spec: corev1.PodSpec{
			ServiceAccountName: "default",
			Containers: []corev1.Container{{
				Name:  "c",
				Image: "nginx:1.27",
			}},
		},
	}
	baseline := admission.Baseline{
		SamplePods:        10,
		SampleContainers:  20,
		DigestPinFraction: 0.3, // below 0.70 threshold
	}
	f := evaluatePod(pod, admission.DefaultChecks(), baseline)
	if len(f.Warnings) > 0 || len(f.DenyReasons) > 0 {
		t.Errorf("thin baseline should silence checks; got warns=%v deny=%v",
			f.Warnings, f.DenyReasons)
	}
}

// TestEvaluatePod_FiresAtHighBaseline verifies that the same risky pod
// trips multiple checks once the baseline indicates the fleet norm is
// strict.
func TestEvaluatePod_FiresAtHighBaseline(t *testing.T) {
	t.Parallel()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
		Spec: corev1.PodSpec{
			ServiceAccountName: "default",
			Containers: []corev1.Container{{
				Name:  "c",
				Image: "nginx:1.27",
			}},
		},
	}
	baseline := admission.Baseline{
		SamplePods:                    100,
		SampleContainers:              500,
		DigestPinFraction:             0.95,
		NonRootFraction:               0.90,
		NoPrivilegeEscalationFraction: 0.85,
		NamedServiceAccountFraction:   0.92,
		ReadOnlyRootFSFraction:        0.80,
	}
	f := evaluatePod(pod, admission.DefaultChecks(), baseline)
	if len(f.Warnings) < 3 {
		t.Errorf("expected several warnings, got %v", f.Warnings)
	}
}

// TestWriteDriftReport_HumanOutput checks the text rendering covers
// header lines and includes findings.
func TestWriteDriftReport_HumanOutput(t *testing.T) {
	t.Parallel()
	report := driftReport{
		Context:     "prod-east",
		TotalPods:   2,
		DriftedPods: 1,
		Findings: []driftFinding{{
			Namespace: "ns",
			Pod:       "p",
			Warnings:  []string{"image not digest-pinned"},
		}},
	}
	buf := &bytes.Buffer{}
	if err := writeDriftReport(buf, report, false); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Context:        prod-east") {
		t.Errorf("missing context line: %s", out)
	}
	if !strings.Contains(out, "[ns/p]") {
		t.Errorf("missing finding header: %s", out)
	}
	if !strings.Contains(out, "image not digest-pinned") {
		t.Errorf("missing warning: %s", out)
	}
}

// TestWriteDriftReport_NoDriftHumanOutput verifies the clean-pass
// message is emitted when there is no drift.
func TestWriteDriftReport_NoDriftHumanOutput(t *testing.T) {
	t.Parallel()
	report := driftReport{Context: "ok", TotalPods: 5, DriftedPods: 0}
	buf := &bytes.Buffer{}
	if err := writeDriftReport(buf, report, false); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(buf.String(), "No drift detected") {
		t.Errorf("missing clean message: %s", buf.String())
	}
}

// TestWriteDriftReport_JSONOutput verifies JSON emission is decodable
// and reflects the report structure.
func TestWriteDriftReport_JSONOutput(t *testing.T) {
	t.Parallel()
	report := driftReport{
		Context:     "c",
		TotalPods:   1,
		DriftedPods: 1,
		Findings: []driftFinding{{
			Namespace: "ns",
			Pod:       "p",
			Warnings:  []string{"w"},
		}},
	}
	buf := &bytes.Buffer{}
	if err := writeDriftReport(buf, report, true); err != nil {
		t.Fatalf("render: %v", err)
	}
	var decoded driftReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Context != "c" || decoded.DriftedPods != 1 ||
		len(decoded.Findings) != 1 || decoded.Findings[0].Pod != "p" {
		t.Errorf("decoded: %+v", decoded)
	}
}
