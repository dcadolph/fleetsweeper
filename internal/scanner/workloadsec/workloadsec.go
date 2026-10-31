// Package workloadsec implements the scanner that audits pod security contexts across all
// namespaces.
package workloadsec

import (
	"cmp"
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/podsec"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "workload-security"

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
	// PrivilegedContainers is containers, ephemeral included, running with privileged=true.
	PrivilegedContainers int `json:"privileged_containers"`
	// HostNetworkPods is pods using the host network namespace.
	HostNetworkPods int `json:"host_network_pods"`
	// HostPIDPods is pods using the host PID namespace.
	HostPIDPods int `json:"host_pid_pods"`
	// HostIPCPods is pods using the host IPC namespace.
	HostIPCPods int `json:"host_ipc_pods"`
	// HostPathVolumes is pods that mount a hostPath volume.
	HostPathVolumes int `json:"host_path_volumes"`
	// BaselineContainers is the init and regular containers, the denominator of every count
	// that feeds the admission baseline. Ephemeral containers are left out, since admission
	// never sees them.
	BaselineContainers int `json:"baseline_containers"`
	// RunAsRootContainers is baseline containers whose effective runAsUser is 0.
	RunAsRootContainers int `json:"run_as_root_containers"`
	// RunAsNonRootContainers is baseline containers explicitly non-root, by an effective
	// runAsUser above 0, or an unset one under an effective runAsNonRoot of true.
	RunAsNonRootContainers int `json:"run_as_non_root_containers"`
	// RunAsUnknownContainers is baseline containers whose spec does not settle the user, so
	// only the image can.
	RunAsUnknownContainers int `json:"run_as_unknown_containers"`
	// CapabilityAdditions is containers, ephemeral included, that add Linux capabilities beyond
	// the default set.
	CapabilityAdditions int `json:"capability_additions"`
	// MissingCapabilityDropAll is containers, ephemeral included, that do not drop ALL
	// capabilities.
	MissingCapabilityDropAll int `json:"missing_capability_drop_all"`
	// AllowPrivilegeEscalation is baseline containers that may gain privileges, by an unset or
	// true allowPrivilegeEscalation, privileged, or an added CAP_SYS_ADMIN.
	AllowPrivilegeEscalation int `json:"allow_privilege_escalation"`
	// MissingSeccompProfile is containers, ephemeral included, not confined by a RuntimeDefault
	// or Localhost seccomp profile.
	MissingSeccompProfile int `json:"missing_seccomp_profile"`
	// NoReadOnlyRoot is baseline containers without a read-only root filesystem.
	NoReadOnlyRoot int `json:"no_read_only_root"`
	// DefaultServiceAccountPods is pods using the namespace's default ServiceAccount.
	DefaultServiceAccountPods int `json:"default_service_account_pods"`
	// HighRiskPods lists the containers, ephemeral included, with the most concerning security
	// postures.
	HighRiskPods []PodRisk `json:"high_risk_pods"`
}

// NewScanner returns a scanner that audits pod security contexts across all namespaces.
func NewScanner() scanner.Scanner {
	return scanner.Func(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		var cov scanner.Coverage
		pods, err := scanner.ListAll(ctx, scanner.CacheReadOptions(), client.Clientset().CoreV1().Pods("").List,
			func(l *corev1.PodList) []corev1.Pod { return l.Items })
		if !cov.Observe("pods", err) {
			return cov.Finish(Name, nil)
		}

		data := Data{TotalPods: len(pods)}

		for i := range pods {
			pod := &pods[i]
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

			baseline := len(pod.Spec.InitContainers) + len(pod.Spec.Containers)
			data.BaselineContainers += baseline
			for j, c := range podsec.Containers(pod, true) {
				var risks []string
				sc := c.SecurityContext
				inBaseline := j < baseline

				if sc != nil && sc.Privileged != nil && *sc.Privileged {
					data.PrivilegedContainers++
					risks = append(risks, "privileged")
				}

				status := podsec.RootStatus(pod, c)
				if status == podsec.Root {
					risks = append(risks, "runs-as-root")
				}
				if inBaseline {
					switch status {
					case podsec.Root:
						data.RunAsRootContainers++
					case podsec.NonRoot:
						data.RunAsNonRootContainers++
					default:
						data.RunAsUnknownContainers++
					}
				}

				if sc != nil && sc.Capabilities != nil && len(sc.Capabilities.Add) > 0 {
					data.CapabilityAdditions++
					risks = append(risks, fmt.Sprintf("capabilities-add:%v", sc.Capabilities.Add))
				}
				if !podsec.DropsAllCapabilities(c) {
					data.MissingCapabilityDropAll++
				}
				escalates := podsec.AllowsPrivilegeEscalation(c)
				if escalates {
					if inBaseline {
						data.AllowPrivilegeEscalation++
					}
					risks = append(risks, "allow-privilege-escalation")
				}
				if !podsec.SeccompConfined(pod, c) {
					data.MissingSeccompProfile++
				}
				if !podsec.ReadOnlyRootFS(c) {
					if inBaseline {
						data.NoReadOnlyRoot++
					}
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
					escalates
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

		data.HighRiskPods = scanner.TopN(data.HighRiskPods, 50, comparePodRisks)

		return cov.Finish(Name, data)
	})
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

// comparePodRisks orders pod risks by risk count, most first, then by namespace, pod, and
// container.
func comparePodRisks(a, b PodRisk) int {
	return cmp.Or(
		cmp.Compare(len(b.Risks), len(a.Risks)),
		cmp.Compare(a.Namespace, b.Namespace),
		cmp.Compare(a.Pod, b.Pod),
		cmp.Compare(a.Container, b.Container),
	)
}
