package workloadsec

import (
	"context"
	"fmt"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dcadolph/fleetsweeper/internal/kube"
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
	// PrivilegedContainers is containers running with privileged=true.
	PrivilegedContainers int `json:"privileged_containers"`
	// HostNetworkPods is pods using the host network namespace.
	HostNetworkPods int `json:"host_network_pods"`
	// HostPIDPods is pods using the host PID namespace.
	HostPIDPods int `json:"host_pid_pods"`
	// RunAsRootContainers is containers running as root (UID 0) or without a non-root constraint.
	RunAsRootContainers int `json:"run_as_root_containers"`
	// CapabilityAdditions is containers that add Linux capabilities beyond the default set.
	CapabilityAdditions int `json:"capability_additions"`
	// NoReadOnlyRoot is containers without a read-only root filesystem.
	NoReadOnlyRoot int `json:"no_read_only_root"`
	// HighRiskPods lists pods with the most concerning security postures.
	HighRiskPods []PodRisk `json:"high_risk_pods"`
}

// NewScanner returns a scanner that audits pod security contexts across all namespaces.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		podList, err := client.Clientset().CoreV1().Pods("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: %w", scanner.ErrScan, Name, err)
		}

		data := Data{TotalPods: len(podList.Items)}

		for _, pod := range podList.Items {
			hostNet := pod.Spec.HostNetwork
			hostPID := pod.Spec.HostPID
			if hostNet {
				data.HostNetworkPods++
			}
			if hostPID {
				data.HostPIDPods++
			}

			for _, c := range append(pod.Spec.InitContainers, pod.Spec.Containers...) {
				var risks []string
				sc := c.SecurityContext

				if sc != nil && sc.Privileged != nil && *sc.Privileged {
					data.PrivilegedContainers++
					risks = append(risks, "privileged")
				}

				runAsRoot := true
				if sc != nil && sc.RunAsNonRoot != nil && *sc.RunAsNonRoot {
					runAsRoot = false
				}
				if sc != nil && sc.RunAsUser != nil && *sc.RunAsUser != 0 {
					runAsRoot = false
				}
				if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsNonRoot != nil && *pod.Spec.SecurityContext.RunAsNonRoot {
					runAsRoot = false
				}
				if runAsRoot {
					data.RunAsRootContainers++
					risks = append(risks, "may-run-as-root")
				}

				if sc != nil && sc.Capabilities != nil && len(sc.Capabilities.Add) > 0 {
					data.CapabilityAdditions++
					risks = append(risks, fmt.Sprintf("capabilities-add:%v", sc.Capabilities.Add))
				}

				readOnly := false
				if sc != nil && sc.ReadOnlyRootFilesystem != nil && *sc.ReadOnlyRootFilesystem {
					readOnly = true
				}
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

				// Only track high-risk pods (privileged, host access, or capabilities).
				isHighRisk := (sc != nil && sc.Privileged != nil && *sc.Privileged) || hostNet || hostPID ||
					(sc != nil && sc.Capabilities != nil && len(sc.Capabilities.Add) > 0)
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
