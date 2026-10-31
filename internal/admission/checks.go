package admission

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/dcadolph/fleetsweeper/internal/podsec"
)

// DefaultChecks returns the built-in fleet-norm checks. They lean on the
// image-audit and workload-sec scanners' aggregate outputs, which the
// baseline provider converts into per-property fractions.
func DefaultChecks() []Check {
	return []Check{
		digestPinCheck{},
		nonRootCheck{},
		noPrivEscCheck{},
		namedSACheck{},
		readOnlyRootFSCheck{},
	}
}

// namedSACheck flags pods running under the default ServiceAccount when
// most of the fleet uses named SAs (a common indicator that an
// application accidentally regressed to the namespace default).
type namedSACheck struct{}

// Name returns the check identifier.
func (namedSACheck) Name() string { return "named-service-account" }

// Evaluate inspects spec.serviceAccountName.
func (namedSACheck) Evaluate(pod *corev1.Pod, b Baseline) ([]string, string) {
	if b.NamedServiceAccountFraction < Threshold {
		return nil, ""
	}
	sa := pod.Spec.ServiceAccountName
	if sa != "" && sa != "default" {
		return nil, ""
	}
	pct := int(b.NamedServiceAccountFraction * 100)
	msg := fmt.Sprintf("named-service-account: %d%% of fleet pods use a named ServiceAccount; this pod uses the namespace default",
		pct)
	return []string{msg}, msg
}

// readOnlyRootFSCheck flags containers whose root filesystem is writable
// when the fleet norm is read-only roots.
type readOnlyRootFSCheck struct{}

// Name returns the check identifier.
func (readOnlyRootFSCheck) Name() string { return "read-only-root-fs" }

// Evaluate flags each admitted container whose root filesystem is not read-only.
func (readOnlyRootFSCheck) Evaluate(pod *corev1.Pod, b Baseline) ([]string, string) {
	if b.ReadOnlyRootFSFraction < Threshold {
		return nil, ""
	}
	var offenders []string
	for _, c := range admittedContainers(pod) {
		if !podsec.ReadOnlyRootFS(c) {
			offenders = append(offenders, c.Name)
		}
	}
	if len(offenders) == 0 {
		return nil, ""
	}
	pct := int(b.ReadOnlyRootFSFraction * 100)
	msg := fmt.Sprintf("read-only-root-fs: %d%% of fleet containers run with a read-only root filesystem; %d here do not (%s)",
		pct, len(offenders), strings.Join(offenders, ", "))
	return []string{msg}, msg
}

// digestPinCheck flags containers without a digest reference when most of
// the fleet pins their images.
type digestPinCheck struct{}

// Name returns the check identifier.
func (digestPinCheck) Name() string { return "digest-pin" }

// Evaluate inspects every container reference for a digest segment.
func (digestPinCheck) Evaluate(pod *corev1.Pod, b Baseline) ([]string, string) {
	if b.DigestPinFraction < Threshold {
		return nil, ""
	}
	var offenders []string
	for _, c := range admittedContainers(pod) {
		if !strings.Contains(c.Image, "@sha256:") {
			offenders = append(offenders, c.Name+"="+c.Image)
		}
	}
	if len(offenders) == 0 {
		return nil, ""
	}
	pct := int(b.DigestPinFraction * 100)
	msg := fmt.Sprintf("digest-pin: %d%% of fleet containers pin images by digest; %d here do not (%s)",
		pct, len(offenders), strings.Join(offenders, ", "))
	return []string{msg}, msg
}

// nonRootCheck flags containers that are not explicitly non-root when most of the fleet is.
type nonRootCheck struct{}

// Name returns the check identifier.
func (nonRootCheck) Name() string { return "non-root" }

// Evaluate flags each admitted container whose effective user is not explicitly non-root, the
// same predicate the baseline fraction counts. Container settings win over pod settings.
func (nonRootCheck) Evaluate(pod *corev1.Pod, b Baseline) ([]string, string) {
	if b.NonRootFraction < Threshold {
		return nil, ""
	}
	var offenders []string
	for _, c := range admittedContainers(pod) {
		if podsec.RootStatus(pod, c) != podsec.NonRoot {
			offenders = append(offenders, c.Name)
		}
	}
	if len(offenders) == 0 {
		return nil, ""
	}
	pct := int(b.NonRootFraction * 100)
	msg := fmt.Sprintf("non-root: %d%% of fleet containers run as non-root; %d here do not (%s)",
		pct, len(offenders), strings.Join(offenders, ", "))
	return []string{msg}, msg
}

// noPrivEscCheck flags containers that may gain privileges when most of the fleet cannot.
type noPrivEscCheck struct{}

// Name returns the check identifier.
func (noPrivEscCheck) Name() string { return "no-privilege-escalation" }

// Evaluate flags each admitted container that may gain privileges, which an unset
// allowPrivilegeEscalation allows.
func (noPrivEscCheck) Evaluate(pod *corev1.Pod, b Baseline) ([]string, string) {
	if b.NoPrivilegeEscalationFraction < Threshold {
		return nil, ""
	}
	var offenders []string
	for _, c := range admittedContainers(pod) {
		if podsec.AllowsPrivilegeEscalation(c) {
			offenders = append(offenders, c.Name)
		}
	}
	if len(offenders) == 0 {
		return nil, ""
	}
	pct := int(b.NoPrivilegeEscalationFraction * 100)
	msg := fmt.Sprintf("no-privilege-escalation: %d%% of fleet containers set allowPrivilegeEscalation=false; %d here do not (%s)",
		pct, len(offenders), strings.Join(offenders, ", "))
	return []string{msg}, msg
}

// admittedContainers returns the init and regular containers of a pod being created. Ephemeral
// containers are left out on purpose: they arrive later through the ephemeralcontainers
// subresource, never on pod create, so admission never sees them.
func admittedContainers(pod *corev1.Pod) []corev1.Container {
	return podsec.Containers(pod, false)
}
