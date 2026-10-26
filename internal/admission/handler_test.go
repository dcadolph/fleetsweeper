package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

// TestWriteUnevaluatedNilLog verifies writeUnevaluated emits an allow
// response with a warning and does not panic when the handler has no logger.
func TestWriteUnevaluatedNilLog(t *testing.T) {
	t.Parallel()
	h := &Handler{}
	rec := httptest.NewRecorder()
	h.writeUnevaluated(rec, "abc", context.DeadlineExceeded)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out admissionv1.AdmissionReview
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Response == nil || !out.Response.Allowed {
		t.Fatalf("writeUnevaluated should allow, got %+v", out.Response)
	}
	if string(out.Response.UID) != "abc" {
		t.Errorf("uid = %q, want abc", out.Response.UID)
	}
	if len(out.Response.Warnings) != 1 {
		t.Errorf("want one warning, got %v", out.Response.Warnings)
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
		WantUID     string
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
		{ // Test 4: Invalid JSON is allowed with a warning in enforce mode.
			Name: "invalid-json-enforce", Body: []byte("{ not valid json "), Baseline: sufficientBaseline,
			Mode: ModeEnforce, WantStatus: 200, WantAllowed: true, WantWarn: true, WantUID: "-",
		},
		{ // Test 5: A missing request payload is allowed with a warning in enforce mode.
			Name: "nil-request-enforce", Body: nilRequestBody(t), Baseline: sufficientBaseline,
			Mode: ModeEnforce, WantStatus: 200, WantAllowed: true, WantWarn: true, WantUID: "-",
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
		{ // Test 8: Invalid JSON is allowed with a warning in advisory mode.
			Name: "invalid-json-advisory", Body: []byte("{ not valid json "), Baseline: sufficientBaseline,
			Mode: ModeAdvisory, WantStatus: 200, WantAllowed: true, WantWarn: true, WantUID: "-",
		},
		{ // Test 9: A missing request payload is allowed with a warning in advisory mode.
			Name: "nil-request-advisory", Body: nilRequestBody(t), Baseline: sufficientBaseline,
			Mode: ModeAdvisory, WantStatus: 200, WantAllowed: true, WantWarn: true, WantUID: "-",
		},
		{ // Test 10: An unrecognized mode behaves as advisory: warn, never deny.
			Name: "unknown-mode", Body: reviewBody(t, dirtyPod()), Baseline: sufficientBaseline,
			Mode: Mode("Enforce"), WantStatus: 200, WantAllowed: true, WantWarn: true, WantResult: false,
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
			// A review with a request echoes its UID; one without has none to echo.
			wantUID := "u"
			if test.WantUID == "-" {
				wantUID = ""
			}
			if string(out.Response.UID) != wantUID {
				t.Errorf("test %d (%s): uid = %q, want %q", testNum, test.Name, out.Response.UID, wantUID)
			}
		})
	}
}

// TestBaselineSufficient pins the sample gate at 30 containers and 10 pods.
func TestBaselineSufficient(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Containers int
		Pods       int
		WantResult bool
	}{
		{Containers: 29, Pods: 10, WantResult: false}, // Test 0: One container short.
		{Containers: 30, Pods: 9, WantResult: false},  // Test 1: One pod short.
		{Containers: 30, Pods: 10, WantResult: true},  // Test 2: Exactly at both floors.
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			b := Baseline{SampleContainers: test.Containers, SamplePods: test.Pods}
			if diff := cmp.Diff(test.WantResult, b.Sufficient()); diff != "" {
				t.Errorf("sufficient mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestCheckThresholdBoundary verifies every default check stays silent at a
// fleet fraction of 0.69 and fires at 0.70 against a pod that violates it.
func TestCheckThresholdBoundary(t *testing.T) {
	t.Parallel()
	set := map[string]func(*Baseline, float64){
		"named-service-account":   func(b *Baseline, f float64) { b.NamedServiceAccountFraction = f },
		"read-only-root-fs":       func(b *Baseline, f float64) { b.ReadOnlyRootFSFraction = f },
		"digest-pin":              func(b *Baseline, f float64) { b.DigestPinFraction = f },
		"non-root":                func(b *Baseline, f float64) { b.NonRootFraction = f },
		"no-privilege-escalation": func(b *Baseline, f float64) { b.NoPrivilegeEscalationFraction = f },
	}
	pod := dirtyPod()
	testNum := 0
	for _, chk := range DefaultChecks() {
		setter, ok := set[chk.Name()]
		if !ok {
			t.Fatalf("no fraction setter for check %q", chk.Name())
		}
		for _, row := range []struct {
			Fraction float64
			WantFire bool
		}{{Fraction: 0.69, WantFire: false}, {Fraction: 0.70, WantFire: true}} {
			t.Run(fmt.Sprintf("test %d %s %.2f", testNum, chk.Name(), row.Fraction), func(t *testing.T) {
				t.Parallel()
				b := Baseline{SamplePods: 50, SampleContainers: 100}
				setter(&b, row.Fraction)
				warnings, deny := chk.Evaluate(&pod, b)
				if gotFire := len(warnings) > 0 && deny != ""; gotFire != row.WantFire {
					t.Errorf("fire = %v, want %v (warnings %v, deny %q)", gotFire, row.WantFire, warnings, deny)
				}
			})
			testNum++
		}
	}
}

// TestNewHandler verifies the constructor applies the body cap default and panics on missing
// dependencies.
func TestNewHandler(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Provider     BaselineProvider
		Log          *zap.Logger
		WantPanic    bool
		WantMaxBytes int64
	}{{ // Test 0: Every dependency present sets the 1 MiB default.
		Provider: fakeProvider{b: sufficientBaseline}, Log: zap.NewNop(), WantMaxBytes: 1 << 20,
	}, { // Test 1: A nil provider panics.
		Log: zap.NewNop(), WantPanic: true,
	}, { // Test 2: A nil logger panics.
		Provider: fakeProvider{b: sufficientBaseline}, WantPanic: true,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			defer func() {
				if r := recover(); (r != nil) != test.WantPanic {
					t.Errorf("panic = %v, want panic %v", r, test.WantPanic)
				}
			}()
			h := NewHandler(test.Provider, DefaultChecks(), ModeEnforce, test.Log)
			if h.MaxBytes != test.WantMaxBytes {
				t.Errorf("MaxBytes = %d, want %d", h.MaxBytes, test.WantMaxBytes)
			}
		})
	}
}

// TestHandlerZeroMaxBytesConcurrent verifies a literal Handler with no MaxBytes serves concurrent
// requests without writing to itself, which the race detector would report.
func TestHandlerZeroMaxBytesConcurrent(t *testing.T) {
	t.Parallel()
	h := &Handler{Provider: fakeProvider{b: sufficientBaseline}, Checks: DefaultChecks(), Mode: ModeAdvisory,
		Log: zap.NewNop()}
	body := reviewBody(t, dirtyPod())
	done := make(chan int, 8)
	for range 8 {
		go func() {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body)))
			done <- rec.Code
		}()
	}
	for range 8 {
		if code := <-done; code != http.StatusOK {
			t.Errorf("status = %d, want 200", code)
		}
	}
	if h.MaxBytes != 0 {
		t.Errorf("ServeHTTP mutated MaxBytes to %d", h.MaxBytes)
	}
}
