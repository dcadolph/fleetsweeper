package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// fakeProvider returns a canned Baseline for tests.
type fakeProvider struct{ b Baseline }

// Current implements BaselineProvider.
func (f fakeProvider) Current(_ context.Context) Baseline { return f.b }

// TestDigestPinCheck verifies the digest-pin check fires when the baseline
// fraction is high and an offending container is present.
func TestDigestPinCheck(t *testing.T) {
	t.Parallel()
	chk := digestPinCheck{}
	pod := &corev1.Pod{Spec: corev1.PodSpec{
		Containers: []corev1.Container{{Name: "c", Image: "nginx:1.27"}},
	}}
	warns, deny := chk.Evaluate(pod, Baseline{DigestPinFraction: 0.9})
	if len(warns) == 0 || deny == "" {
		t.Errorf("expected warning + deny, got %v / %q", warns, deny)
	}

	// Baseline below threshold suppresses the warning.
	warns, deny = chk.Evaluate(pod, Baseline{DigestPinFraction: 0.3})
	if len(warns) > 0 || deny != "" {
		t.Errorf("expected silence below threshold, got %v / %q", warns, deny)
	}

	// Digest-pinned image is clean even at high baseline.
	pin := &corev1.Pod{Spec: corev1.PodSpec{
		Containers: []corev1.Container{{Name: "c", Image: "nginx@sha256:abc"}},
	}}
	warns, deny = chk.Evaluate(pin, Baseline{DigestPinFraction: 0.9})
	if len(warns) > 0 || deny != "" {
		t.Errorf("pinned pod should pass, got %v / %q", warns, deny)
	}
}

// TestNamedSACheck verifies the named-service-account check fires on
// pods using the default ServiceAccount.
func TestNamedSACheck(t *testing.T) {
	t.Parallel()
	chk := namedSACheck{}
	defaultPod := &corev1.Pod{Spec: corev1.PodSpec{ServiceAccountName: "default"}}
	if warns, _ := chk.Evaluate(defaultPod, Baseline{NamedServiceAccountFraction: 0.9}); len(warns) == 0 {
		t.Error("default SA should warn at high baseline")
	}
	namedPod := &corev1.Pod{Spec: corev1.PodSpec{ServiceAccountName: "frontend"}}
	if warns, _ := chk.Evaluate(namedPod, Baseline{NamedServiceAccountFraction: 0.9}); len(warns) > 0 {
		t.Errorf("named SA should pass, got %v", warns)
	}
}

// TestReadOnlyRootFSCheck verifies the read-only-root-fs check fires on
// writable rootfs containers at high baseline.
func TestReadOnlyRootFSCheck(t *testing.T) {
	t.Parallel()
	chk := readOnlyRootFSCheck{}
	writable := &corev1.Pod{Spec: corev1.PodSpec{
		Containers: []corev1.Container{{Name: "c"}},
	}}
	if warns, _ := chk.Evaluate(writable, Baseline{ReadOnlyRootFSFraction: 0.9}); len(warns) == 0 {
		t.Error("writable rootfs should warn at high baseline")
	}
	yes := true
	readonly := &corev1.Pod{Spec: corev1.PodSpec{
		Containers: []corev1.Container{{
			Name:            "c",
			SecurityContext: &corev1.SecurityContext{ReadOnlyRootFilesystem: &yes},
		}},
	}}
	if warns, _ := chk.Evaluate(readonly, Baseline{ReadOnlyRootFSFraction: 0.9}); len(warns) > 0 {
		t.Errorf("read-only rootfs should pass, got %v", warns)
	}
}

// TestNonRootCheck verifies pod-level and container-level runAsNonRoot
// behavior.
func TestNonRootCheck(t *testing.T) {
	t.Parallel()
	chk := nonRootCheck{}
	yes := true
	podLevel := &corev1.Pod{Spec: corev1.PodSpec{
		SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: &yes},
		Containers:      []corev1.Container{{Name: "c"}},
	}}
	warns, _ := chk.Evaluate(podLevel, Baseline{NonRootFraction: 0.9})
	if len(warns) > 0 {
		t.Errorf("pod-level runAsNonRoot should pass, got %v", warns)
	}

	noSC := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}}}
	warns, _ = chk.Evaluate(noSC, Baseline{NonRootFraction: 0.9})
	if len(warns) == 0 {
		t.Error("missing security context should warn at high baseline")
	}
}

// TestHandlerAdvisoryAllows verifies advisory mode always allows even when
// a check fires.
func TestHandlerAdvisoryAllows(t *testing.T) {
	t.Parallel()
	h := &Handler{
		Provider: fakeProvider{b: Baseline{
			SamplePods: 50, SampleContainers: 100,
			DigestPinFraction: 0.95,
		}},
		Checks: DefaultChecks(),
		Mode:   ModeAdvisory,
		Log:    zap.NewNop(),
	}
	resp := h.evaluate(context.Background(), buildPodRequest(t, "nginx:1.27"))
	if !resp.Allowed {
		t.Error("advisory mode should allow")
	}
	if len(resp.Warnings) == 0 {
		t.Error("advisory mode should still warn")
	}
}

// TestHandlerEnforceDenies verifies enforce mode denies when a check fires.
func TestHandlerEnforceDenies(t *testing.T) {
	t.Parallel()
	h := &Handler{
		Provider: fakeProvider{b: Baseline{
			SamplePods: 50, SampleContainers: 100,
			DigestPinFraction: 0.95,
		}},
		Checks: DefaultChecks(),
		Mode:   ModeEnforce,
		Log:    zap.NewNop(),
	}
	resp := h.evaluate(context.Background(), buildPodRequest(t, "nginx:1.27"))
	if resp.Allowed {
		t.Error("enforce mode should deny on offending pod")
	}
	if resp.Result == nil || resp.Result.Message == "" {
		t.Error("denied response should carry a reason")
	}
}

// TestHandlerInsufficientBaselineAllows verifies a thin baseline yields
// allow plus a benign warning rather than a deny.
func TestHandlerInsufficientBaselineAllows(t *testing.T) {
	t.Parallel()
	h := &Handler{
		Provider: fakeProvider{b: Baseline{
			SamplePods: 1, SampleContainers: 2,
			DigestPinFraction: 1.0,
		}},
		Checks: DefaultChecks(),
		Mode:   ModeEnforce,
		Log:    zap.NewNop(),
	}
	resp := h.evaluate(context.Background(), buildPodRequest(t, "nginx:1.27"))
	if !resp.Allowed {
		t.Error("thin baseline should not deny")
	}
}

// TestHandlerServeHTTPRoundTrip exercises the full HTTP path with a real
// JSON-encoded AdmissionReview.
func TestHandlerServeHTTPRoundTrip(t *testing.T) {
	t.Parallel()
	h := &Handler{
		Provider: fakeProvider{b: Baseline{SamplePods: 100, SampleContainers: 500, DigestPinFraction: 0.9}},
		Checks:   DefaultChecks(),
		Mode:     ModeAdvisory,
		Log:      zap.NewNop(),
	}
	body := encodeAdmissionReview(t, "nginx:1.27")
	req := httptest.NewRequest(http.MethodPost, "/admission/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var out admissionv1.AdmissionReview
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Response == nil || !out.Response.Allowed {
		t.Errorf("expected allowed, got %+v", out.Response)
	}
}

// buildPodRequest produces an AdmissionRequest pointing at a Pod whose
// only container is named "c" and uses the supplied image reference.
func buildPodRequest(t *testing.T, image string) *admissionv1.AdmissionRequest {
	t.Helper()
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "c", Image: image}},
		},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return &admissionv1.AdmissionRequest{
		UID:    types.UID("test-uid"),
		Kind:   metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
		Object: runtime.RawExtension{Raw: raw},
	}
}

// encodeAdmissionReview wraps a buildPodRequest output in an AdmissionReview JSON body.
func encodeAdmissionReview(t *testing.T, image string) []byte {
	t.Helper()
	in := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request:  buildPodRequest(t, image),
	}
	body, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal review: %v", err)
	}
	return body
}
