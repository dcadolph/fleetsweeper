package workloadsec

import (
	"context"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "workload-security"

// Root status values describe what we know about a container's identity.
const (
	// RootStatusRoot means the container is explicitly configured to run as UID 0.
	RootStatusRoot = "root"
	// RootStatusNonRoot means the container is configured to run as a non-root user.
	RootStatusNonRoot = "non-root"
	// RootStatusUnknown means neither the pod nor the container specifies a user.
	// We cannot tell without inspecting the image, so we report this honestly
	// rather than defaulting to "root" (which produced enormous false positives).
	RootStatusUnknown = "unknown"
)

// PodRisk describes a pod with a security concern.
type PodRisk struct {
	// Namespace is the pod's namespace.
	Namespace string `json:"namespace"`
	// Pod is the pod name.
	Pod string `json:"pod"`
	// Container is the container name within the pod.
	Container string `json:"container"`
	// Risks lists the specific security risks found.
	Risks []string `json:"risks"`
}

// Data holds workload security audit results for one cluster.
type Data struct {
	// TotalPods is the number of pods scanned.
	TotalPods int `json:"total_pods"`
	// PrivilegedContainers is containers running with privileged=true.
	PrivilegedContainers int `json:"privileged_containers"`
	// HostNetworkPods is pods using the host network namespace.
	HostNetworkPods int `json:"host_network_pods"`
	// HostPIDPods is pods using the host PID namespace.
	HostPIDPods int `json:"host_pid_pods"`
	// HostIPCPods is pods using the host IPC namespace.
	HostIPCPods int `json:"host_ipc_pods"`
	// HostPathVolumes is pods that mount a hostPath volume.
	HostPathVolumes int `json:"host_path_volumes"`
	// RunAsRootContainers is containers explicitly configured to run as UID 0.
	RunAsRootContainers int `json:"run_as_root_containers"`
	// UnknownRootContainers is containers without explicit user configuration.
	// These may or may not run as root depending on the image; flag them as
	// "unknown" so operators can audit selectively rather than treating every
	// undeclared workload as a violation.
	UnknownRootContainers int `json:"unknown_root_containers"`
	// CapabilityAdditions is containers that add Linux capabilities beyond the default set.
	CapabilityAdditions int `json:"capability_additions"`
	// MissingCapabilityDropAll is containers that do not drop ALL capabilities.
	MissingCapabilityDropAll int `json:"missing_capability_drop_all"`
	// AllowPrivilegeEscalation is containers that do not explicitly set
	// allowPrivilegeEscalation=false (the field defaults to true, which is
	// the PSS-restricted defining check).
	AllowPrivilegeEscalation int `json:"allow_privilege_escalation"`
	// MissingSeccompProfile is containers/pods without an explicit seccomp profile.
	MissingSeccompProfile int `json:"missing_seccomp_profile"`
	// NoReadOnlyRoot is containers without a read-only root filesystem.
	NoReadOnlyRoot int `json:"no_read_only_root"`
	// DefaultServiceAccountPods is pods using the namespace's default ServiceAccount.
	DefaultServiceAccountPods int `json:"default_service_account_pods"`
	// HighRiskPods lists pods with the most concerning security postures.
	HighRiskPods []PodRisk `json:"high_risk_pods"`
}

// NewScanner returns a scanner that audits pod security contexts across all namespaces.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		podList, err := client.Clientset().CoreV1().Pods("").List(ctx, metav1.ListOptions{
			ResourceVersion:      "0",
			ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		})
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: %w", scanner.ErrScan, Name, err)
		}

		data := Data{TotalPods: len(podList.Items)}

		for i := range podList.Items {
			pod := &podList.Items[i]
			hostNet := pod.Spec.HostNetwork
			hostPID := pod.Spec.HostPID
			hostIPC := pod.Spec.HostIPC
			if hostNet {
				data.HostNetworkPods++
			}
			if hostPID {
				data.HostPIDPods++
			}
			if hostIPC {
				data.HostIPCPods++
			}
			if hasHostPath(pod) {
				data.HostPathVolumes++
			}
			if pod.Spec.ServiceAccountName == "" || pod.Spec.ServiceAccountName == "default" {
				data.DefaultServiceAccountPods++
			}

			containers := allContainers(pod)
			for _, c := range containers {
				var risks []string
				sc := c.SecurityContext

				if sc != nil && sc.Privileged != nil && *sc.Privileged {
					data.PrivilegedContainers++
					risks = append(risks, "privileged")
				}

				switch rootStatus(pod, sc) {
				case RootStatusRoot:
					data.RunAsRootContainers++
					risks = append(risks, "runs-as-root")
				case RootStatusUnknown:
					data.UnknownRootContainers++
				}

				if sc != nil && sc.Capabilities != nil && len(sc.Capabilities.Add) > 0 {
					data.CapabilityAdditions++
					risks = append(risks, fmt.Sprintf("capabilities-add:%v", sc.Capabilities.Add))
				}
				if !dropsAllCapabilities(sc) {
					data.MissingCapabilityDropAll++
				}
				if allowsPrivilegeEscalation(sc) {
					data.AllowPrivilegeEscalation++
					risks = append(risks, "allow-privilege-escalation")
				}
				if !hasSeccompProfile(pod, sc) {
					data.MissingSeccompProfile++
				}

				readOnly := sc != nil && sc.ReadOnlyRootFilesystem != nil && *sc.ReadOnlyRootFilesystem
				if !readOnly {
					data.NoReadOnlyRoot++
					risks = append(risks, "writable-root-fs")
				}

				if hostNet {
					risks = append(risks, "host-network")
				}
				if hostPID {
					risks = append(risks, "host-pid")
				}
				if hostIPC {
					risks = append(risks, "host-ipc")
				}

				isHighRisk := (sc != nil && sc.Privileged != nil && *sc.Privileged) ||
					hostNet || hostPID || hostIPC ||
					(sc != nil && sc.Capabilities != nil && len(sc.Capabilities.Add) > 0) ||
					allowsPrivilegeEscalation(sc)
				if isHighRisk {
					data.HighRiskPods = append(data.HighRiskPods, PodRisk{
						Namespace: pod.Namespace,
						Pod:       pod.Name,
						Container: c.Name,
						Risks:     risks,
					})
				}
			}
		}

		sort.Slice(data.HighRiskPods, func(i, j int) bool {
			return len(data.HighRiskPods[i].Risks) > len(data.HighRiskPods[j].Risks)
		})
		if len(data.HighRiskPods) > 50 {
			data.HighRiskPods = data.HighRiskPods[:50]
		}

		return scanner.Result{Scanner: Name, Data: data}, nil
	})
}

// allContainers returns every container that can run in the pod: init,
// regular, and ephemeral. The previous implementation ignored ephemeral
// containers entirely, which hid the kubectl-debug attack surface.
func allContainers(pod *corev1.Pod) []corev1.Container {
	out := make([]corev1.Container, 0, len(pod.Spec.InitContainers)+len(pod.Spec.Containers)+len(pod.Spec.EphemeralContainers))
	out = append(out, pod.Spec.InitContainers...)
	out = append(out, pod.Spec.Containers...)
	for _, ec := range pod.Spec.EphemeralContainers {
		out = append(out, corev1.Container{
			Name:            ec.Name,
			Image:           ec.Image,
			Command:         ec.Command,
			Args:            ec.Args,
			SecurityContext: ec.SecurityContext,
		})
	}
	return out
}

// rootStatus classifies a container's effective user. We prefer explicit
// pod-level then container-level signals; only when neither is present do we
// return Unknown rather than guess.
func rootStatus(pod *corev1.Pod, sc *corev1.SecurityContext) string {
	if sc != nil && sc.RunAsUser != nil {
		if *sc.RunAsUser == 0 {
			return RootStatusRoot
		}
		return RootStatusNonRoot
	}
	if sc != nil && sc.RunAsNonRoot != nil {
		if *sc.RunAsNonRoot {
			return RootStatusNonRoot
		}
		return RootStatusRoot
	}
	if pod.Spec.SecurityContext != nil {
		if pod.Spec.SecurityContext.RunAsUser != nil {
			if *pod.Spec.SecurityContext.RunAsUser == 0 {
				return RootStatusRoot
			}
			return RootStatusNonRoot
		}
		if pod.Spec.SecurityContext.RunAsNonRoot != nil {
			if *pod.Spec.SecurityContext.RunAsNonRoot {
				return RootStatusNonRoot
			}
			return RootStatusRoot
		}
	}
	return RootStatusUnknown
}

// allowsPrivilegeEscalation reports whether the container allows escalation.
// The field defaults to true when unset, which is the PSS-restricted
// defining check. Setting privileged=true forces the field to true as well.
func allowsPrivilegeEscalation(sc *corev1.SecurityContext) bool {
	if sc == nil {
		return true
	}
	if sc.Privileged != nil && *sc.Privileged {
		return true
	}
	if sc.AllowPrivilegeEscalation == nil {
		return true
	}
	return *sc.AllowPrivilegeEscalation
}

// dropsAllCapabilities reports whether the container drops ALL capabilities.
// The PSS-baseline standard requires this explicit drop.
func dropsAllCapabilities(sc *corev1.SecurityContext) bool {
	if sc == nil || sc.Capabilities == nil {
		return false
	}
	for _, drop := range sc.Capabilities.Drop {
		if drop == "ALL" || drop == "all" {
			return true
		}
	}
	return false
}

// hasSeccompProfile reports whether either the pod or container has an
// explicit seccomp profile set. RuntimeDefault and Localhost both satisfy
// PSS-baseline.
func hasSeccompProfile(pod *corev1.Pod, sc *corev1.SecurityContext) bool {
	if sc != nil && sc.SeccompProfile != nil && sc.SeccompProfile.Type != "" && sc.SeccompProfile.Type != corev1.SeccompProfileTypeUnconfined {
		return true
	}
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SeccompProfile != nil &&
		pod.Spec.SecurityContext.SeccompProfile.Type != "" &&
		pod.Spec.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeUnconfined {
		return true
	}
	return false
}

// hasHostPath reports whether the pod mounts a hostPath volume.
func hasHostPath(pod *corev1.Pod) bool {
	for _, v := range pod.Spec.Volumes {
		if v.HostPath != nil {
			return true
		}
	}
	return false
}
