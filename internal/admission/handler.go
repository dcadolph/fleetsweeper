package admission

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

// Handler serves the /admission/validate endpoint. One instance per
// process. Safe for concurrent use; the underlying baseline cache is
// guarded internally.
type Handler struct {
	// Provider supplies the fleet baseline.
	Provider BaselineProvider
	// Checks is the ordered list of fleet-norm checks to evaluate.
	Checks []Check
	// Mode selects advisory vs enforce semantics.
	Mode Mode
	// Log is the structured logger.
	Log *zap.Logger
	// MaxBytes caps the request body the handler will read. Defaults to
	// 1 MiB which matches the apiserver's default.
	MaxBytes int64
}

// codecs is the shared serializer factory used to decode incoming
// AdmissionReview JSON.
var codecs = serializer.NewCodecFactory(runtimeScheme())

// runtimeScheme builds a minimal scheme covering only the types the
// admission handler decodes.
func runtimeScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(admissionv1.AddToScheme(s))
	utilruntime.Must(corev1.AddToScheme(s))
	return s
}

// gvk is the GroupVersionKind for AdmissionReview responses.
var admissionReviewGVK = schema.GroupVersionKind{
	Group: admissionv1.SchemeGroupVersion.Group, Version: admissionv1.SchemeGroupVersion.Version, Kind: "AdmissionReview",
}

// ServeHTTP implements http.Handler. It decodes the AdmissionReview,
// evaluates each registered check, and encodes the response.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.MaxBytes <= 0 {
		h.MaxBytes = 1 << 20
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.MaxBytes))
	if err != nil {
		http.Error(w, fmt.Sprintf("read body: %v", err), http.StatusBadRequest)
		return
	}
	in := &admissionv1.AdmissionReview{}
	if _, _, err := codecs.UniversalDeserializer().Decode(body, nil, in); err != nil {
		h.writeFailure(w, "", fmt.Errorf("decode: %w", err))
		return
	}
	if in.Request == nil {
		h.writeFailure(w, "", errors.New("missing request"))
		return
	}

	resp := h.evaluate(r.Context(), in.Request)
	out := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: admissionReviewGVK.GroupVersion().String(), Kind: admissionReviewGVK.Kind},
		Response: resp,
	}
	body, err = json.Marshal(out)
	if err != nil {
		h.Log.Warn("encode admission response failed", zap.Error(err))
		http.Error(w, "encode failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(body); err != nil {
		h.Log.Debug("admission write failed", zap.Error(err))
	}
}

// evaluate runs every check against the incoming pod and returns an
// AdmissionResponse honoring the configured Mode.
func (h *Handler) evaluate(ctx context.Context, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	resp := &admissionv1.AdmissionResponse{UID: req.UID, Allowed: true}

	pod, err := decodePod(req)
	if err != nil {
		h.Log.Warn("admission: decode pod", zap.Error(err))
		resp.Warnings = append(resp.Warnings, "fleetsweeper: failed to decode pod; allowing")
		return resp
	}

	baseline := h.Provider.Current(ctx)
	if !baseline.Sufficient() {
		resp.Warnings = append(resp.Warnings,
			"fleetsweeper: baseline below sample threshold; not evaluating")
		return resp
	}

	var denies []string
	for _, chk := range h.Checks {
		ws, deny := chk.Evaluate(pod, baseline)
		for _, w := range ws {
			resp.Warnings = append(resp.Warnings, "fleetsweeper: "+w)
		}
		if deny != "" {
			denies = append(denies, deny)
		}
	}

	if h.Mode == ModeEnforce && len(denies) > 0 {
		resp.Allowed = false
		resp.Result = &metav1.Status{
			Status:  metav1.StatusFailure,
			Reason:  metav1.StatusReasonForbidden,
			Message: "fleetsweeper enforce: " + joinDenies(denies),
		}
	}
	return resp
}

// writeFailure writes a deny response carrying the supplied error. The
// apiserver treats it as a webhook failure but still records the message
// for cluster operators.
func (h *Handler) writeFailure(w http.ResponseWriter, uid string, err error) {
	if h.Log != nil {
		h.Log.Warn("admission handler error", zap.Error(err))
	}
	out := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: admissionReviewGVK.GroupVersion().String(), Kind: admissionReviewGVK.Kind},
		Response: &admissionv1.AdmissionResponse{
			UID:     types.UID(uid),
			Allowed: false,
			Result:  &metav1.Status{Status: metav1.StatusFailure, Message: err.Error()},
		},
	}
	body, marshalErr := json.Marshal(out)
	if marshalErr != nil {
		http.Error(w, "encode failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// decodePod returns the corev1.Pod carried in the AdmissionRequest.
func decodePod(req *admissionv1.AdmissionRequest) (*corev1.Pod, error) {
	if req.Kind.Kind != "Pod" {
		return nil, fmt.Errorf("expected Pod, got %s", req.Kind.Kind)
	}
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return nil, fmt.Errorf("unmarshal pod: %w", err)
	}
	return &pod, nil
}

// joinDenies stitches multiple deny messages together with a separator.
func joinDenies(in []string) string {
	if len(in) == 0 {
		return ""
	}
	if len(in) == 1 {
		return in[0]
	}
	var out strings.Builder
	out.WriteString(in[0])
	for _, m := range in[1:] {
		out.WriteString("; " + m)
	}
	return out.String()
}
