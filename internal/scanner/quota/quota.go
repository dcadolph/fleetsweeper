// Package quota inspects ResourceQuota and LimitRange coverage across namespaces.
package quota

import (
	"context"
	"sort"

	corev1 "k8s.io/api/core/v1"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "resource-quotas"

// Info describes a single ResourceQuota.
type Info struct {
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
	Quotas []Info `json:"quotas"`
	// LimitRanges lists all LimitRanges.
	LimitRanges []LimitRangeInfo `json:"limit_ranges"`
}

// NewScanner returns a scanner that collects ResourceQuota and LimitRange data.
func NewScanner() scanner.Scanner {
	return scanner.Func(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		var cov scanner.Coverage
		cs := client.Clientset()
		qList, err := scanner.ListAll(ctx, scanner.CacheReadOptions(), cs.CoreV1().ResourceQuotas("").List,
			func(l *corev1.ResourceQuotaList) []corev1.ResourceQuota { return l.Items })
		if !cov.Require("resource quotas", err) {
			qList = nil
		}

		lrList, err := scanner.ListAll(ctx, scanner.CacheReadOptions(), cs.CoreV1().LimitRanges("").List,
			func(l *corev1.LimitRangeList) []corev1.LimitRange { return l.Items })
		if !cov.Require("limit ranges", err) {
			lrList = nil
		}

		namespacesWithQuotas := make(map[string]struct{})
		quotas := make([]Info, 0, len(qList))
		for _, q := range qList {
			namespacesWithQuotas[q.Namespace] = struct{}{}
			hard := make(map[string]string, len(q.Spec.Hard))
			for k, v := range q.Spec.Hard {
				hard[string(k)] = v.String()
			}
			used := make(map[string]string, len(q.Status.Used))
			for k, v := range q.Status.Used {
				used[string(k)] = v.String()
			}
			quotas = append(quotas, Info{
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

		limitRanges := make([]LimitRangeInfo, 0, len(lrList))
		for _, lr := range lrList {
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

		return cov.Finish(Name, Data{
			QuotaCount:           len(quotas),
			LimitRangeCount:      len(limitRanges),
			NamespacesWithQuotas: len(namespacesWithQuotas),
			Quotas:               quotas,
			LimitRanges:          limitRanges,
		})
	})
}
