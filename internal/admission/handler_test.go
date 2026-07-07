package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"

	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// sufficientBaseline is a fleet norm dense enough to activate every check.
var sufficientBaseline = Baseline{
	SamplePods: 50, SampleContainers: 100,
	DigestPinFraction:             0.95,
	NonRootFraction:               0.95,
	NoPrivilegeEscalationFraction: 0.95,
	NamedServiceAccountFraction:   0.95,
	ReadOnlyRootFSFraction:        0.95,
}

// dirtyPod returns a pod that violates every baseline check: an unpinned
// image, the default ServiceAccount, and no security context.
func dirtyPod() corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
		Spec: corev1.PodSpec{
			ServiceAccountName: "default",
			Containers:         []corev1.Container{{Name: "c", Image: "nginx:1.27"}},
		},
	}
}

// cleanPod returns a pod that satisfies every baseline check.
func cleanPod() corev1.Pod {
	yes := true
	no := false
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
		Spec: corev1.PodSpec{
			ServiceAccountName: "frontend",
			SecurityContext:    &corev1.PodSecurityContext{RunAsNonRoot: &yes},
			Containers: []corev1.Container{{
				Name:  "c",
				Image: "nginx@sha256:abc",
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: &no,
					ReadOnlyRootFilesystem:   &yes,
				},
			}},
		},
	}
}

// reviewBody marshals a Pod into an AdmissionReview request body.
func reviewBody(t *testing.T, pod corev1.Pod) []byte {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("marshal pod: %v", err)
	}
	return reviewBodyKind(t, "Pod", raw)
}

// reviewBodyKind wraps a raw object of the given kind in an AdmissionReview.
func reviewBodyKind(t *testing.T, kind string, raw []byte) []byte {
	t.Helper()
	in := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:    types.UID("u"),
			Kind:   metav1.GroupVersionKind{Version: "v1", Kind: kind},
			Object: runtime.RawExtension{Raw: raw},
		},
	}
	body, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal review: %v", err)
	}
	return body
}

// nilRequestBody produces an AdmissionReview with no Request payload.
func nilRequestBody(t *testing.T) []byte {
	t.Helper()
	body, err := json.Marshal(admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
	})
	if err != nil {
		t.Fatalf("marshal review: %v", err)
	}
	return body
}

// TestJoinDenies verifies the deny joiner handles empty, single, and multiple
// messages.
func TestJoinDenies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WantResult string
		In         []string
	}{
		{In: nil, WantResult: ""},                            // Test 0: Empty.
		{In: []string{"only"}, WantResult: "only"},           // Test 1: Single.
		{In: []string{"a", "b", "c"}, WantResult: "a; b; c"}, // Test 2: Multiple joined.
	}
	for testNum, test := range tests {
		t.Run("test", func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(test.WantResult, joinDenies(test.In)); diff != "" {
				t.Errorf("test %d mismatch (-want +got):\n%s", testNum, diff)
			}
		})
	}
}

// TestDecodePod verifies the pod decoder rejects non-Pod kinds and malformed
// payloads while accepting a valid pod.
func TestDecodePod(t *testing.T) {
	t.Parallel()
	validRaw, err := json.Marshal(cleanPod())
	if err != nil {
		t.Fatalf("marshal pod: %v", err)
	}
	tests := []struct {
		Req     *admissionv1.AdmissionRequest
		WantErr bool
	}{
		{ // Test 0: Non-Pod kind is rejected.
			Req:     &admissionv1.AdmissionRequest{Kind: metav1.GroupVersionKind{Kind: "Deployment"}},
			WantErr: true,
		},
		{ // Test 1: Malformed pod JSON is rejected.
			Req: &admissionv1.AdmissionRequest{
				Kind:   metav1.GroupVersionKind{Kind: "Pod"},
				Object: runtime.RawExtension{Raw: []byte("{not json")},
			},
			WantErr: true,
		},
		{ // Test 2: Valid pod decodes cleanly.
			Req: &admissionv1.AdmissionRequest{
				Kind:   metav1.GroupVersionKind{Kind: "Pod"},
				Object: runtime.RawExtension{Raw: validRaw},
			},
			WantErr: false,
		},
	}
	for testNum, test := range tests {
		t.Run("test", func(t *testing.T) {
			t.Parallel()
			pod, err := decodePod(test.Req)
			if (err != nil) != test.WantErr {
				t.Errorf("test %d: err = %v, wantErr = %v", testNum, err, test.WantErr)
			}
			if !test.WantErr && pod == nil {
				t.Errorf("test %d: expected a pod on success", testNum)
			}
		})
	}
}

// TestHandlerEvaluateDecodeError verifies a request the handler cannot decode
// into a pod is allowed with an explanatory warning rather than denied.
func TestHandlerEvaluateDecodeError(t *testing.T) {
	t.Parallel()
	h := &Handler{
		Provider: fakeProvider{b: sufficientBaseline},
		Checks:   DefaultChecks(),
		Mode:     ModeEnforce,
		Log:      zap.NewNop(),
	}
	req := &admissionv1.AdmissionRequest{
		UID:  types.UID("u"),
		Kind: metav1.GroupVersionKind{Kind: "Deployment"},
	}
	resp := h.evaluate(context.Background(), req)
	if !resp.Allowed {
		t.Error("undecodable pod should be allowed")
	}
	if len(resp.Warnings) == 0 {
		t.Error("undecodable pod should carry a warning")
	}
}

// TestWriteFailureNilLog verifies writeFailure emits a deny response and does
// not panic when the handler has no logger.
func TestWriteFailureNilLog(t *testing.T) {
	t.Parallel()
	h := &Handler{}
	rec := httptest.NewRecorder()
	h.writeFailure(rec, "abc", context.DeadlineExceeded)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out admissionv1.AdmissionReview
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Response == nil || out.Response.Allowed {
		t.Fatalf("writeFailure should deny, got %+v", out.Response)
	}
	if string(out.Response.UID) != "abc" {
		t.Errorf("uid = %q, want abc", out.Response.UID)
	}
	if out.Response.Result == nil || out.Response.Result.Message == "" {
		t.Error("failure response should carry a message")
	}
}

// TestHandlerServeHTTPCases exercises the full HTTP round trip across allowed,
// warned, denied, and malformed-request outcomes.
func TestHandlerServeHTTPCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name        string
		Body        []byte
		Baseline    Baseline
		Mode        Mode
		MaxBytes    int64
		WantStatus  int
		WantAllowed bool
		WantWarn    bool
		WantResult  bool
	}{
		{ // Test 0: Advisory mode warns but allows an offending pod.
			Name: "advisory-dirty", Body: reviewBody(t, dirtyPod()), Baseline: sufficientBaseline,
			Mode: ModeAdvisory, WantStatus: 200, WantAllowed: true, WantWarn: true, WantResult: false,
		},
		{ // Test 1: Enforce mode denies (and still warns on) an offending pod.
			Name: "enforce-dirty", Body: reviewBody(t, dirtyPod()), Baseline: sufficientBaseline,
			Mode: ModeEnforce, WantStatus: 200, WantAllowed: false, WantWarn: true, WantResult: true,
		},
		{ // Test 2: Enforce mode allows a fully compliant pod without comment.
			Name: "enforce-clean", Body: reviewBody(t, cleanPod()), Baseline: sufficientBaseline,
			Mode: ModeEnforce, WantStatus: 200, WantAllowed: true, WantWarn: false, WantResult: false,
		},
		{ // Test 3: A thin baseline allows with a threshold warning even in enforce mode.
			Name: "insufficient", Body: reviewBody(t, dirtyPod()),
			Baseline: Baseline{SamplePods: 1, SampleContainers: 2, DigestPinFraction: 1},
			Mode:     ModeEnforce, WantStatus: 200, WantAllowed: true, WantWarn: true, WantResult: false,
		},
		{ // Test 4: Invalid JSON produces a deny failure response.
			Name: "invalid-json", Body: []byte("{ not valid json "), Baseline: sufficientBaseline,
			Mode: ModeEnforce, WantStatus: 200, WantAllowed: false, WantResult: true,
		},
		{ // Test 5: A missing request payload produces a deny failure response.
			Name: "nil-request", Body: nilRequestBody(t), Baseline: sufficientBaseline,
			Mode: ModeEnforce, WantStatus: 200, WantAllowed: false, WantResult: true,
		},
		{ // Test 6: A non-Pod object is allowed with a decode warning.
			Name: "non-pod-kind", Body: reviewBodyKind(t, "Deployment", []byte(`{"kind":"Deployment"}`)),
			Baseline: sufficientBaseline, Mode: ModeEnforce,
			WantStatus: 200, WantAllowed: true, WantWarn: true, WantResult: false,
		},
		{ // Test 7: A body past the size cap is rejected before decoding.
			Name: "too-large", Body: reviewBody(t, dirtyPod()), Baseline: sufficientBaseline,
			Mode: ModeEnforce, MaxBytes: 8, WantStatus: http.StatusBadRequest,
		},
	}
	for testNum, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			h := &Handler{
				Provider: fakeProvider{b: test.Baseline},
				Checks:   DefaultChecks(),
				Mode:     test.Mode,
				Log:      zap.NewNop(),
				MaxBytes: test.MaxBytes,
			}
			req := httptest.NewRequest(http.MethodPost, "/admission/validate", bytes.NewReader(test.Body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != test.WantStatus {
				t.Fatalf("test %d (%s): status = %d, want %d", testNum, test.Name, rec.Code, test.WantStatus)
			}
			if test.WantStatus != http.StatusOK {
				return
			}
			var out admissionv1.AdmissionReview
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatalf("test %d (%s): decode: %v", testNum, test.Name, err)
			}
			if out.Response == nil {
				t.Fatalf("test %d (%s): nil response", testNum, test.Name)
			}
			if out.Response.Allowed != test.WantAllowed {
				t.Errorf("test %d (%s): allowed = %v, want %v", testNum, test.Name, out.Response.Allowed, test.WantAllowed)
			}
			if gotWarn := len(out.Response.Warnings) > 0; gotWarn != test.WantWarn {
				t.Errorf("test %d (%s): warn = %v, want %v (%v)", testNum, test.Name, gotWarn, test.WantWarn, out.Response.Warnings)
			}
			gotResult := out.Response.Result != nil && out.Response.Result.Message != ""
			if gotResult != test.WantResult {
				t.Errorf("test %d (%s): result = %v, want %v", testNum, test.Name, gotResult, test.WantResult)
			}
		})
	}
}
