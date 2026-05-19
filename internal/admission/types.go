// Package admission implements the Fleetsweeper ValidatingAdmissionWebhook.
// It compares pod specs presented to the API server against a baseline
// derived from the fleet's most recent scan and either warns (advisory
// mode) or denies (enforce mode) when a pod deviates from the fleet norm.
package admission

import (
	corev1 "k8s.io/api/core/v1"
)

// Mode selects whether the webhook warns or denies on baseline deviations.
type Mode string

const (
	// ModeAdvisory annotates the response with warnings but always allows.
	ModeAdvisory Mode = "advisory"
	// ModeEnforce denies admission when a check fires.
	ModeEnforce Mode = "enforce"
)

// Baseline is the fleet-derived norm the webhook checks against. The
// numbers express the fraction of containers across the fleet's most recent
// scan that satisfy each property; values close to 1 mean almost every
// container is doing the safe thing.
type Baseline struct {
	// SamplePods is the number of pods analysed.
	SamplePods int `json:"sample_pods" yaml:"sample_pods"`
	// SampleContainers is the number of containers analysed.
	SampleContainers int `json:"sample_containers" yaml:"sample_containers"`
	// DigestPinFraction is the share of containers using @sha256: digest pins.
	DigestPinFraction float64 `json:"digest_pin_fraction" yaml:"digest_pin_fraction"`
	// NonRootFraction is the share of containers not declared to run as UID 0.
	NonRootFraction float64 `json:"non_root_fraction" yaml:"non_root_fraction"`
	// NoPrivilegeEscalationFraction is the share of containers with
	// allowPrivilegeEscalation set false (the PSS-restricted check).
	NoPrivilegeEscalationFraction float64 `json:"no_privilege_escalation_fraction" yaml:"no_privilege_escalation_fraction"`
	// NamedServiceAccountFraction is the share of pods using a named
	// ServiceAccount (not "default").
	NamedServiceAccountFraction float64 `json:"named_service_account_fraction" yaml:"named_service_account_fraction"`
	// ReadOnlyRootFSFraction is the share of containers with
	// readOnlyRootFilesystem=true.
	ReadOnlyRootFSFraction float64 `json:"read_only_root_fs_fraction" yaml:"read_only_root_fs_fraction"`
	// SourceScanID is the scan the baseline was derived from.
	SourceScanID string `json:"source_scan_id,omitempty" yaml:"source_scan_id,omitempty"`
}

// Sufficient reports whether the baseline has enough data to make a
// confident comparison. The webhook short-circuits to allow when the
// baseline is too thin so a freshly-installed Fleetsweeper does not block
// every admission against an empty norm.
func (b Baseline) Sufficient() bool {
	return b.SampleContainers >= 30 && b.SamplePods >= 10
}

// Threshold is the minimum baseline fraction that activates a check. Above
// this fraction, a violation is meaningful; below it, the fleet itself is
// inconsistent and the check stays quiet.
const Threshold = 0.70

// Decision is the outcome of evaluating a pod against the baseline.
type Decision struct {
	// Allowed mirrors the AdmissionResponse.Allowed semantic. Always true
	// when mode is advisory.
	Allowed bool
	// Reason is a short message returned to the client when Allowed is false.
	Reason string
	// Warnings are the per-check messages surfaced as Kubernetes warnings.
	Warnings []string
}

// Check is one fleet-norm comparator. The webhook runs every registered
// Check against the incoming pod, aggregates the warnings, and (in enforce
// mode) denies admission when at least one check fires.
type Check interface {
	// Name identifies the check in log lines and metrics.
	Name() string
	// Evaluate returns warnings and (when applicable) a deny message.
	// An empty warnings slice means the pod is consistent with the fleet.
	Evaluate(pod *corev1.Pod, baseline Baseline) (warnings []string, denyReason string)
}
