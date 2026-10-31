// Package podsec evaluates pod and container security settings with Kubernetes precedence, so
// every scanner and admission check that asks the same question gets the same answer.
package podsec

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// Status describes what a pod spec settles about the user a container runs as.
type Status string

// Status values. Unknown counts as not non-root for every consumer.
const (
	// Root means the effective runAsUser is 0.
	Root Status = "root"
	// NonRoot means the effective runAsNonRoot is true or the effective runAsUser is above 0.
	NonRoot Status = "non-root"
	// Unknown means the spec does not settle the user, so only the image can.
	Unknown Status = "unknown"
)

// podContext returns the pod-level security context, or nil when the pod or its context is
// absent.
func podContext(pod *corev1.Pod) *corev1.PodSecurityContext {
	if pod == nil {
		return nil
	}
	return pod.Spec.SecurityContext
}

// RunAsNonRoot returns the effective runAsNonRoot and whether either level sets it. The container
// value wins when set, else the pod value applies.
func RunAsNonRoot(pod *corev1.Pod, c corev1.Container) (bool, bool) {
	if sc := c.SecurityContext; sc != nil && sc.RunAsNonRoot != nil {
		return *sc.RunAsNonRoot, true
	}
	if psc := podContext(pod); psc != nil && psc.RunAsNonRoot != nil {
		return *psc.RunAsNonRoot, true
	}
	return false, false
}

// RunAsUser returns the effective runAsUser and whether either level sets it. The container value
// wins when set, else the pod value applies.
func RunAsUser(pod *corev1.Pod, c corev1.Container) (int64, bool) {
	if sc := c.SecurityContext; sc != nil && sc.RunAsUser != nil {
		return *sc.RunAsUser, true
	}
	if psc := podContext(pod); psc != nil && psc.RunAsUser != nil {
		return *psc.RunAsUser, true
	}
	return 0, false
}

// RootStatus classifies the container's user from the effective runAsUser and runAsNonRoot. An
// effective runAsUser of 0 is Root even under runAsNonRoot true, since that container cannot run
// as anything else, and runAsNonRoot false alone is Unknown because false only skips the check.
func RootStatus(pod *corev1.Pod, c corev1.Container) Status {
	uid, uidSet := RunAsUser(pod, c)
	if uidSet && uid == 0 {
		return Root
	}
	if nonRoot, _ := RunAsNonRoot(pod, c); nonRoot {
		return NonRoot
	}
	if uidSet && uid > 0 {
		return NonRoot
	}
	return Unknown
}

// AllowsPrivilegeEscalation reports whether the container may gain privileges. An unset field is
// true, and privileged or an added CAP_SYS_ADMIN (or ALL) forces true whatever the field says.
func AllowsPrivilegeEscalation(c corev1.Container) bool {
	sc := c.SecurityContext
	if sc == nil || sc.AllowPrivilegeEscalation == nil {
		return true
	}
	if sc.Privileged != nil && *sc.Privileged {
		return true
	}
	if sc.Capabilities != nil {
		for _, add := range sc.Capabilities.Add {
			name := strings.TrimPrefix(strings.ToUpper(string(add)), "CAP_")
			if name == "SYS_ADMIN" || name == "ALL" {
				return true
			}
		}
	}
	return *sc.AllowPrivilegeEscalation
}

// ReadOnlyRootFS reports whether the container's root filesystem is read-only. The field exists
// only on the container and an unset field means writable.
func ReadOnlyRootFS(c corev1.Container) bool {
	sc := c.SecurityContext
	return sc != nil && sc.ReadOnlyRootFilesystem != nil && *sc.ReadOnlyRootFilesystem
}

// DropsAllCapabilities reports whether the container drops ALL capabilities, matched without
// regard to case as container runtimes do. The field exists only on the container.
func DropsAllCapabilities(c corev1.Container) bool {
	sc := c.SecurityContext
	if sc == nil || sc.Capabilities == nil {
		return false
	}
	for _, drop := range sc.Capabilities.Drop {
		if strings.EqualFold(string(drop), "ALL") {
			return true
		}
	}
	return false
}

// SeccompConfined reports whether the container runs under a RuntimeDefault or Localhost seccomp
// profile. The container profile wins when set, Unconfined included, else the pod profile
// applies, and no profile at either level is not confined.
func SeccompConfined(pod *corev1.Pod, c corev1.Container) bool {
	var profile *corev1.SeccompProfile
	if psc := podContext(pod); psc != nil {
		profile = psc.SeccompProfile
	}
	if sc := c.SecurityContext; sc != nil && sc.SeccompProfile != nil {
		profile = sc.SeccompProfile
	}
	if profile == nil {
		return false
	}
	switch profile.Type {
	case corev1.SeccompProfileTypeRuntimeDefault, corev1.SeccompProfileTypeLocalhost:
		return true
	default:
		return false
	}
}

// Containers returns the pod's init and regular containers, followed by its ephemeral containers
// converted to Container when includeEphemeral is true. It returns nil for a nil pod.
func Containers(pod *corev1.Pod, includeEphemeral bool) []corev1.Container {
	if pod == nil {
		return nil
	}
	spec := &pod.Spec
	n := len(spec.InitContainers) + len(spec.Containers)
	if includeEphemeral {
		n += len(spec.EphemeralContainers)
	}
	out := make([]corev1.Container, 0, n)
	out = append(out, spec.InitContainers...)
	out = append(out, spec.Containers...)
	if includeEphemeral {
		for i := range spec.EphemeralContainers {
			out = append(out, corev1.Container(spec.EphemeralContainers[i].EphemeralContainerCommon))
		}
	}
	return out
}
