package quota

import (
	"context"
	"fmt"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "resource-quotas"

// QuotaInfo describes a single ResourceQuota.
type QuotaInfo struct {
	// Namespace is the namespace containing the quota.
	Namespace string `json:"namespace"`
	// Name is the quota name.
	Name string `json:"name"`
	// Hard maps resource names to their hard limits.
	Hard map[string]string `json:"hard"`
	// Used maps resource names to their current usage.
	Used map[string]string `json:"used"`
}

// LimitRangeInfo describes a single LimitRange.
type LimitRangeInfo struct {
	// Namespace is the namespace containing the limit range.
	Namespace string `json:"namespace"`
	// Name is the limit range name.
	Name string `json:"name"`
	// ItemCount is the number of limit items defined.
	ItemCount int `json:"item_count"`
}

// Data holds resource quota and limit range information for one cluster.
type Data struct {
	// QuotaCount is the number of ResourceQuotas.
	QuotaCount int `json:"quota_count"`
	// LimitRangeCount is the number of LimitRanges.
	LimitRangeCount int `json:"limit_range_count"`
	// NamespacesWithQuotas is how many namespaces have at least one quota.
	NamespacesWithQuotas int `json:"namespaces_with_quotas"`
	// Quotas lists all ResourceQuotas.
	Quotas []QuotaInfo `json:"quotas"`
	// LimitRanges lists all LimitRanges.
	LimitRanges []LimitRangeInfo `json:"limit_ranges"`
}

// NewScanner returns a scanner that collects ResourceQuota and LimitRange data.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		qList, err := client.Clientset().CoreV1().ResourceQuotas("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: quotas: %w", scanner.ErrScan, Name, err)
		}

		lrList, err := client.Clientset().CoreV1().LimitRanges("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: limit ranges: %w", scanner.ErrScan, Name, err)
		}

		namespacesWithQuotas := make(map[string]struct{})
		quotas := make([]QuotaInfo, 0, len(qList.Items))
		for _, q := range qList.Items {
			namespacesWithQuotas[q.Namespace] = struct{}{}
			hard := make(map[string]string, len(q.Spec.Hard))
			for k, v := range q.Spec.Hard {
				hard[string(k)] = v.String()
			}
			used := make(map[string]string, len(q.Status.Used))
			for k, v := range q.Status.Used {
				used[string(k)] = v.String()
			}
			quotas = append(quotas, QuotaInfo{
				Namespace: q.Namespace,
				Name:      q.Name,
				Hard:      hard,
				Used:      used,
			})
		}
		sort.Slice(quotas, func(i, j int) bool {
			if quotas[i].Namespace != quotas[j].Namespace {
				return quotas[i].Namespace < quotas[j].Namespace
			}
			return quotas[i].Name < quotas[j].Name
		})

		limitRanges := make([]LimitRangeInfo, 0, len(lrList.Items))
		for _, lr := range lrList.Items {
			limitRanges = append(limitRanges, LimitRangeInfo{
				Namespace: lr.Namespace,
				Name:      lr.Name,
				ItemCount: len(lr.Spec.Limits),
			})
		}
		sort.Slice(limitRanges, func(i, j int) bool {
			if limitRanges[i].Namespace != limitRanges[j].Namespace {
				return limitRanges[i].Namespace < limitRanges[j].Namespace
			}
			return limitRanges[i].Name < limitRanges[j].Name
		})

		return scanner.Result{
			Scanner: Name,
			Data: Data{
				QuotaCount:           len(quotas),
				LimitRangeCount:      len(limitRanges),
				NamespacesWithQuotas: len(namespacesWithQuotas),
				Quotas:               quotas,
				LimitRanges:          limitRanges,
			},
		}, nil
	})
}
