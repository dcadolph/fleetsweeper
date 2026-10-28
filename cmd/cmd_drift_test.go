package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/dcadolph/fleetsweeper/internal/admission"
	"github.com/dcadolph/fleetsweeper/internal/kube"
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

// strictDriftBaseline is a baseline whose fleet norm is strict enough to activate every check.
var strictDriftBaseline = admission.Baseline{
	SamplePods:                    100,
	SampleContainers:              500,
	DigestPinFraction:             0.95,
	NonRootFraction:               0.90,
	NoPrivilegeEscalationFraction: 0.85,
	NamedServiceAccountFraction:   0.92,
	ReadOnlyRootFSFraction:        0.80,
}

// driftTestPod returns a pod with default settings that violate a strict baseline.
func driftTestPod(name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"},
		Spec: corev1.PodSpec{
			ServiceAccountName: "default",
			Containers:         []corev1.Container{{Name: "c", Image: "nginx:1.27"}},
		},
	}
}

// TestRunDriftWithClient verifies the drift run over a fake clientset.
func TestRunDriftWithClient(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Opts            driftOptions
		Pods            []*corev1.Pod
		WantOutContains string
		Want            bool
	}{{ // Test 0: No drift with a thin baseline.
		Opts:            driftOptions{Baseline: admission.Baseline{SamplePods: 1}, FailOnDrift: true},
		Pods:            []*corev1.Pod{driftTestPod("p")},
		WantOutContains: "No drift detected",
	}, { // Test 1: One drifting pod prints the report without fail-on-drift.
		Opts:            driftOptions{Baseline: strictDriftBaseline},
		Pods:            []*corev1.Pod{driftTestPod("p")},
		WantOutContains: "[ns/p]",
	}, { // Test 2: One drifting pod errors with fail-on-drift.
		Opts:            driftOptions{Baseline: strictDriftBaseline, FailOnDrift: true},
		Pods:            []*corev1.Pod{driftTestPod("p")},
		WantOutContains: "[ns/p]",
		Want:            true,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			cs := fake.NewSimpleClientset()
			for _, p := range test.Pods {
				if _, err := cs.CoreV1().Pods(p.Namespace).Create(
					context.Background(), p, metav1.CreateOptions{}); err != nil {
					t.Fatalf("create pod: %v", err)
				}
			}
			client := kube.NewTestClientWithClientset("test-ctx", cs)
			out := &bytes.Buffer{}
			err := runDriftWithClient(context.Background(), out, client, test.Opts)
			if diff := cmp.Diff(test.Want, err != nil); diff != "" {
				t.Errorf("error mismatch (-want +got):\n%s (err=%v)", diff, err)
			}
			if !strings.Contains(out.String(), test.WantOutContains) {
				t.Errorf("output missing %q: %s", test.WantOutContains, out.String())
			}
		})
	}
}

// TestResolveDriftBaseline verifies baseline files are validated strictly.
func TestResolveDriftBaseline(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Body          string
		WantErrSubstr string
		WantSamples   int
		Want          bool
	}{{ // Test 0: Valid file loads.
		Body:        "sample_pods: 12\ndigest_pin_fraction: 0.5\n",
		WantSamples: 12,
	}, { // Test 1: Unknown key is an error naming the key.
		Body:          "sample_pods: 12\nbogus_key: 1\n",
		Want:          true,
		WantErrSubstr: "bogus_key",
	}, { // Test 2: Fraction above 1 is an error.
		Body:          "non_root_fraction: 1.5\n",
		Want:          true,
		WantErrSubstr: "non_root_fraction",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "baseline.yaml")
			if err := os.WriteFile(path, []byte(test.Body), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			b, err := resolveDriftBaseline(nil, path)
			if diff := cmp.Diff(test.Want, err != nil); diff != "" {
				t.Fatalf("error mismatch (-want +got):\n%s (err=%v)", diff, err)
			}
			if err != nil {
				if !strings.Contains(err.Error(), test.WantErrSubstr) {
					t.Errorf("error %q missing %q", err, test.WantErrSubstr)
				}
				return
			}
			if diff := cmp.Diff(test.WantSamples, b.SamplePods); diff != "" {
				t.Errorf("samples mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
