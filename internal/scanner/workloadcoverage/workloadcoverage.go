// Package workloadcoverage reports on PDB and HPA coverage of replicated
// workloads. Deployments and StatefulSets running with replicas>1 but no
// matching PodDisruptionBudget will lose all pods during voluntary
// disruptions; the same workloads without an HPA cannot react to load. Both
// are common gaps that only become visible during incidents.
package workloadcoverage

import (
	"context"
	"sort"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "workload-coverage"

// Coverage describes a replicated workload's PDB and HPA presence.
type Coverage struct {
	// Kind is "Deployment" or "StatefulSet".
	Kind string `json:"kind"`
	// Namespace is the workload's namespace.
	Namespace string `json:"namespace"`
	// Name is the workload's name.
	Name string `json:"name"`
	// Replicas is the spec replica count.
	Replicas int32 `json:"replicas"`
	// HasPDB is true when a PodDisruptionBudget selects this workload's pods.
	HasPDB bool `json:"has_pdb"`
	// HasHPA is true when a HorizontalPodAutoscaler targets this workload.
	HasHPA bool `json:"has_hpa"`
}

// Data holds workload coverage results for one cluster.
type Data struct {
	// TotalReplicated is the count of Deployments/StatefulSets with replicas>1.
	TotalReplicated int `json:"total_replicated"`
	// MissingPDB is the count of replicated workloads without a matching PDB.
	MissingPDB int `json:"missing_pdb"`
	// MissingHPA is the count of replicated workloads without an HPA target.
	MissingHPA int `json:"missing_hpa"`
	// Gaps lists workloads with at least one missing element, sorted by name.
	Gaps []Coverage `json:"gaps"`
}

// NewScanner returns a scanner that flags replicated workloads missing PDB or
// HPA coverage. It is read-only and tolerant: a failure listing one resource
// type does not abort the others.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		appsClient := client.Clientset().AppsV1()
		policyClient := client.Clientset().PolicyV1()
		hpaClient := client.Clientset().AutoscalingV2()

		pdbs, _ := policyClient.PodDisruptionBudgets("").List(ctx, metav1.ListOptions{
			ResourceVersion:      "0",
			ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		})
		hpas, _ := hpaClient.HorizontalPodAutoscalers("").List(ctx, metav1.ListOptions{
			ResourceVersion:      "0",
			ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		})

		hpaTargets := make(map[hpaKey]bool)
		if hpas != nil {
			for i := range hpas.Items {
				hpa := &hpas.Items[i]
				hpaTargets[hpaKey{
					Namespace: hpa.Namespace,
					Kind:      hpa.Spec.ScaleTargetRef.Kind,
					Name:      hpa.Spec.ScaleTargetRef.Name,
				}] = true
			}
		}

		data := Data{}

		deployments, _ := appsClient.Deployments("").List(ctx, metav1.ListOptions{
			ResourceVersion:      "0",
			ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		})
		if deployments != nil {
			for i := range deployments.Items {
				d := &deployments.Items[i]
				replicas := int32(1)
				if d.Spec.Replicas != nil {
					replicas = *d.Spec.Replicas
				}
				if replicas <= 1 {
					continue
				}
				data.TotalReplicated++
				cov := Coverage{
					Kind:      "Deployment",
					Namespace: d.Namespace,
					Name:      d.Name,
					Replicas:  replicas,
					HasPDB:    pdbMatches(pdbs, d.Namespace, d.Spec.Template.Labels),
					HasHPA:    hpaTargets[hpaKey{Namespace: d.Namespace, Kind: "Deployment", Name: d.Name}],
				}
				if !cov.HasPDB {
					data.MissingPDB++
				}
				if !cov.HasHPA {
					data.MissingHPA++
				}
				if !cov.HasPDB || !cov.HasHPA {
					data.Gaps = append(data.Gaps, cov)
				}
			}
		}

		statefulSets, _ := appsClient.StatefulSets("").List(ctx, metav1.ListOptions{
			ResourceVersion:      "0",
			ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		})
		if statefulSets != nil {
			for i := range statefulSets.Items {
				ss := &statefulSets.Items[i]
				replicas := int32(1)
				if ss.Spec.Replicas != nil {
					replicas = *ss.Spec.Replicas
				}
				if replicas <= 1 {
					continue
				}
				data.TotalReplicated++
				cov := Coverage{
					Kind:      "StatefulSet",
					Namespace: ss.Namespace,
					Name:      ss.Name,
					Replicas:  replicas,
					HasPDB:    pdbMatches(pdbs, ss.Namespace, ss.Spec.Template.Labels),
					HasHPA:    hpaTargets[hpaKey{Namespace: ss.Namespace, Kind: "StatefulSet", Name: ss.Name}],
				}
				if !cov.HasPDB {
					data.MissingPDB++
				}
				if !cov.HasHPA {
					data.MissingHPA++
				}
				if !cov.HasPDB || !cov.HasHPA {
					data.Gaps = append(data.Gaps, cov)
				}
			}
		}

		sort.Slice(data.Gaps, func(i, j int) bool {
			if data.Gaps[i].Namespace != data.Gaps[j].Namespace {
				return data.Gaps[i].Namespace < data.Gaps[j].Namespace
			}
			return data.Gaps[i].Name < data.Gaps[j].Name
		})
		if len(data.Gaps) > 100 {
			data.Gaps = data.Gaps[:100]
		}

		_ = autoscalingv2.SchemeGroupVersion // ensure the import is used even when no HPAs are present
		return scanner.Result{Scanner: Name, Data: data}, nil
	})
}

// hpaKey identifies an HPA target by namespace, kind, and name.
type hpaKey struct {
	// Namespace of the target workload.
	Namespace string
	// Kind of the scale target reference.
	Kind string
	// Name of the target workload.
	Name string
}

// pdbMatches reports whether any PDB in the workload's namespace selects the
// supplied pod template labels. A nil selector on a PDB never matches; an
// empty selector matches every pod in the namespace.
func pdbMatches(list *policyv1.PodDisruptionBudgetList, namespace string, podLabels map[string]string) bool {
	if list == nil {
		return false
	}
	for i := range list.Items {
		pdb := &list.Items[i]
		if pdb.Namespace != namespace {
			continue
		}
		if pdb.Spec.Selector == nil {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			continue
		}
		if sel.Matches(labels.Set(podLabels)) {
			return true
		}
	}
	return false
}
