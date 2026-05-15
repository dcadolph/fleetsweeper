package security

import (
	"context"
	"fmt"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "security"

// Pod Security Standards label keys.
const (
	labelEnforce      = "pod-security.kubernetes.io/enforce"
	labelEnforceVer   = "pod-security.kubernetes.io/enforce-version"
	labelAudit        = "pod-security.kubernetes.io/audit"
	labelAuditVer     = "pod-security.kubernetes.io/audit-version"
	labelWarn          = "pod-security.kubernetes.io/warn"
	labelWarnVer      = "pod-security.kubernetes.io/warn-version"
)

// NamespaceSecurity describes the Pod Security Standards labels on a namespace.
type NamespaceSecurity struct {
	// Namespace is the namespace name.
	Namespace string `json:"namespace"`
	// Enforce is the enforce level (privileged, baseline, restricted).
	Enforce string `json:"enforce,omitempty"`
	// EnforceVersion is the enforce version.
	EnforceVersion string `json:"enforce_version,omitempty"`
	// Audit is the audit level.
	Audit string `json:"audit,omitempty"`
	// AuditVersion is the audit version.
	AuditVersion string `json:"audit_version,omitempty"`
	// Warn is the warn level.
	Warn string `json:"warn,omitempty"`
	// WarnVersion is the warn version.
	WarnVersion string `json:"warn_version,omitempty"`
}

// Data holds security posture information for one cluster.
type Data struct {
	// NamespaceCount is the total number of namespaces.
	NamespaceCount int `json:"namespace_count"`
	// EnforcedCount is the number of namespaces with a PSS enforce label.
	EnforcedCount int `json:"enforced_count"`
	// UnenorcedCount is the number of namespaces without a PSS enforce label.
	UnenforcedCount int `json:"unenforced_count"`
	// LevelDistribution maps PSS levels to namespace counts.
	LevelDistribution map[string]int `json:"level_distribution"`
	// Namespaces lists per-namespace security details.
	Namespaces []NamespaceSecurity `json:"namespaces"`
}

// NewScanner returns a scanner that checks Pod Security Standards labels on namespaces.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		nsList, err := client.Clientset().CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: %w", scanner.ErrScan, Name, err)
		}

		data := Data{
			NamespaceCount:    len(nsList.Items),
			LevelDistribution: make(map[string]int),
		}

		for _, ns := range nsList.Items {
			sec := NamespaceSecurity{
				Namespace:      ns.Name,
				Enforce:        ns.Labels[labelEnforce],
				EnforceVersion: ns.Labels[labelEnforceVer],
				Audit:          ns.Labels[labelAudit],
				AuditVersion:   ns.Labels[labelAuditVer],
				Warn:           ns.Labels[labelWarn],
				WarnVersion:    ns.Labels[labelWarnVer],
			}
			if sec.Enforce != "" {
				data.EnforcedCount++
				data.LevelDistribution[sec.Enforce]++
			} else {
				data.UnenforcedCount++
				data.LevelDistribution["none"]++
			}
			data.Namespaces = append(data.Namespaces, sec)
		}

		sort.Slice(data.Namespaces, func(i, j int) bool {
			return data.Namespaces[i].Namespace < data.Namespaces[j].Namespace
		})

		return scanner.Result{
			Scanner: Name,
			Data:    data,
		}, nil
	})
}
