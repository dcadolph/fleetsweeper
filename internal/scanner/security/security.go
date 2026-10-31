// Package security audits security-affecting workload configuration: PodSecurityStandards labels, default-deny NetworkPolicy presence, and similar fleet-wide hardening signals.
package security

import (
	"cmp"
	"context"
	"sort"

	corev1 "k8s.io/api/core/v1"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "security"

// Pod Security Standards label keys.
const (
	labelEnforce    = "pod-security.kubernetes.io/enforce"
	labelEnforceVer = "pod-security.kubernetes.io/enforce-version"
	labelAudit      = "pod-security.kubernetes.io/audit"
	labelAuditVer   = "pod-security.kubernetes.io/audit-version"
	labelWarn       = "pod-security.kubernetes.io/warn"
	labelWarnVer    = "pod-security.kubernetes.io/warn-version"
)

// levelPrivileged is the PSS level that enforces nothing.
const levelPrivileged = "privileged"

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
	// EnforcedCount is the number of namespaces with a PSS enforce label above privileged.
	EnforcedCount int `json:"enforced_count"`
	// UnenforcedCount is the number of namespaces with no PSS enforce label or with enforce
	// privileged, which enforces nothing.
	UnenforcedCount int `json:"unenforced_count"`
	// LevelDistribution maps PSS enforce levels to namespace counts, with "none" for unlabeled.
	LevelDistribution map[string]int `json:"level_distribution"`
	// Namespaces lists per-namespace security details.
	Namespaces []NamespaceSecurity `json:"namespaces"`
}

// NewScanner returns a scanner that checks Pod Security Standards labels on namespaces.
func NewScanner() scanner.Scanner {
	return scanner.Func(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		var cov scanner.Coverage
		nsList, err := scanner.ListAll(ctx, scanner.CacheReadOptions(), client.Clientset().CoreV1().Namespaces().List,
			func(l *corev1.NamespaceList) []corev1.Namespace { return l.Items })
		if !cov.Observe("namespaces", err) {
			nsList = nil
		}

		data := Data{
			NamespaceCount:    len(nsList),
			LevelDistribution: make(map[string]int),
		}

		for _, ns := range nsList {
			sec := NamespaceSecurity{
				Namespace:      ns.Name,
				Enforce:        ns.Labels[labelEnforce],
				EnforceVersion: ns.Labels[labelEnforceVer],
				Audit:          ns.Labels[labelAudit],
				AuditVersion:   ns.Labels[labelAuditVer],
				Warn:           ns.Labels[labelWarn],
				WarnVersion:    ns.Labels[labelWarnVer],
			}
			if Enforced(sec.Enforce) {
				data.EnforcedCount++
			} else {
				data.UnenforcedCount++
			}
			data.LevelDistribution[cmp.Or(sec.Enforce, "none")]++
			data.Namespaces = append(data.Namespaces, sec)
		}

		sort.Slice(data.Namespaces, func(i, j int) bool {
			return data.Namespaces[i].Namespace < data.Namespaces[j].Namespace
		})

		return cov.Finish(Name, data)
	})
}

// Enforced reports whether a PSS enforce level restricts pods. An empty level and privileged
// both enforce nothing.
func Enforced(level string) bool {
	return level != "" && level != levelPrivileged
}
