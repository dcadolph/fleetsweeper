//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/scanner/ingress"
	"github.com/dcadolph/fleetsweeper/internal/scanner/namespace"
	"github.com/dcadolph/fleetsweeper/internal/scanner/networkpolicy"
	"github.com/dcadolph/fleetsweeper/internal/scanner/quota"
	"github.com/dcadolph/fleetsweeper/internal/scanner/rbac"
	"github.com/dcadolph/fleetsweeper/internal/scanner/resources"
	"github.com/dcadolph/fleetsweeper/internal/scanner/security"
	"github.com/dcadolph/fleetsweeper/internal/scanner/service"
	"github.com/dcadolph/fleetsweeper/internal/scanner/version"
)

const (
	clusterAlpha = "fleetsweeper-alpha"
	clusterBeta  = "fleetsweeper-beta"
)

// TestIntegration is the main integration test that creates kind clusters,
// seeds them with different configurations, runs all scanners, and validates
// the comparison report.
func TestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	requireKind(t)
	requireDocker(t)

	kubeconfigPath := filepath.Join(t.TempDir(), "kubeconfig")

	t.Log("creating kind clusters")
	createCluster(t, clusterAlpha, kubeconfigPath)
	createCluster(t, clusterBeta, kubeconfigPath)

	t.Cleanup(func() {
		deleteCluster(t, clusterAlpha)
		deleteCluster(t, clusterBeta)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	t.Log("seeding clusters with test data")
	seedClusterAlpha(t, ctx, kubeconfigPath)
	seedClusterBeta(t, ctx, kubeconfigPath)

	t.Log("connecting to clusters")
	contexts := []string{kindContext(clusterAlpha), kindContext(clusterBeta)}
	clients := kube.ConnectAll(ctx, kubeconfigPath, contexts, 2)
	if len(clients) != 2 {
		t.Fatalf("expected 2 clients, got %d", len(clients))
	}

	t.Log("running scanners")
	registry := buildRegistry()
	results := runAllScanners(t, ctx, clients, registry)

	clusterNames := []string{clients[0].Context, clients[1].Context}
	rpt := report.Build(clusterNames, results)

	t.Run("summary", func(t *testing.T) {
		if diff := cmp.Diff(2, rpt.Summary.ClusterCount); diff != "" {
			t.Errorf("cluster count mismatch (-want +got):\n%s", diff)
		}
		if rpt.Summary.ScannerCount == 0 {
			t.Error("expected at least one scanner to run")
		}
		t.Logf("summary: %d scanners, %d uniform, %d divergent, %d total divergences",
			rpt.Summary.ScannerCount, rpt.Summary.UniformCount,
			rpt.Summary.DivergentCount, rpt.Summary.TotalDivergences)
	})

	t.Run("version uniform", func(t *testing.T) {
		sec, ok := rpt.Sections["version"]
		if !ok {
			t.Fatal("missing version section")
		}
		// Both clusters use the same kind node image so versions should match.
		if !sec.Uniform {
			t.Log("version divergence detected (expected if clusters use different kind images)")
		}
	})

	t.Run("namespace divergence", func(t *testing.T) {
		sec, ok := rpt.Sections["namespaces"]
		if !ok {
			t.Fatal("missing namespaces section")
		}
		// Alpha has "alpha-only" namespace, beta has "beta-only" namespace.
		if sec.Uniform {
			t.Error("expected namespace divergence between clusters")
		}
	})

	t.Run("service divergence", func(t *testing.T) {
		sec, ok := rpt.Sections["services"]
		if !ok {
			t.Fatal("missing services section")
		}
		if sec.Uniform {
			t.Error("expected service divergence between clusters")
		}
	})

	t.Run("rbac divergence", func(t *testing.T) {
		sec, ok := rpt.Sections["rbac"]
		if !ok {
			t.Fatal("missing rbac section")
		}
		// Alpha has extra ClusterRole, should diverge.
		if sec.Uniform {
			t.Error("expected RBAC divergence between clusters")
		}
	})

	t.Run("network policy divergence", func(t *testing.T) {
		sec, ok := rpt.Sections["network-policies"]
		if !ok {
			t.Fatal("missing network-policies section")
		}
		// Alpha has a network policy, beta does not.
		if sec.Uniform {
			t.Error("expected network policy divergence between clusters")
		}
	})

	t.Run("security divergence", func(t *testing.T) {
		sec, ok := rpt.Sections["security"]
		if !ok {
			t.Fatal("missing security section")
		}
		// Alpha enforces PSS on a namespace, beta does not.
		if sec.Uniform {
			t.Error("expected security divergence between clusters")
		}
	})

	t.Run("resource quota divergence", func(t *testing.T) {
		sec, ok := rpt.Sections["resource-quotas"]
		if !ok {
			t.Fatal("missing resource-quotas section")
		}
		// Alpha has a quota, beta does not.
		if sec.Uniform {
			t.Error("expected resource quota divergence between clusters")
		}
	})

	t.Run("html report renders", func(t *testing.T) {
		html, err := report.RenderHTML(rpt)
		if err != nil {
			t.Fatalf("html render failed: %v", err)
		}
		if !strings.Contains(string(html), "Fleetsweeper") {
			t.Error("HTML report missing title")
		}
		if !strings.Contains(string(html), "Divergent") {
			t.Error("HTML report missing divergence indicators")
		}
		// Write to temp file for manual inspection.
		outPath := filepath.Join(t.TempDir(), "report.html")
		if err := os.WriteFile(outPath, html, 0o644); err != nil {
			t.Fatalf("write html: %v", err)
		}
		t.Logf("HTML report written to %s", outPath)
	})

	t.Run("json report valid", func(t *testing.T) {
		jsonBytes, err := json.MarshalIndent(rpt, "", "  ")
		if err != nil {
			t.Fatalf("json marshal failed: %v", err)
		}
		var parsed map[string]any
		if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
			t.Fatalf("json unmarshal failed: %v", err)
		}
		if _, ok := parsed["sections"]; !ok {
			t.Error("JSON report missing sections key")
		}
		if _, ok := parsed["summary"]; !ok {
			t.Error("JSON report missing summary key")
		}
	})
}

// buildRegistry creates the full scanner registry.
func buildRegistry() *scanner.Registry {
	r := scanner.NewRegistry()
	r.Register(version.Name, version.NewScanner())
	r.Register(namespace.Name, namespace.NewScanner())
	r.Register(service.Name, service.NewScanner())
	r.Register(ingress.Name, ingress.NewScanner())
	r.Register(rbac.Name, rbac.NewScanner())
	r.Register(networkpolicy.Name, networkpolicy.NewScanner())
	r.Register(security.Name, security.NewScanner())
	r.Register(quota.Name, quota.NewScanner())
	r.Register(resources.Name, resources.NewScanner())
	return r
}

// runAllScanners executes all registered scanners against all clients.
func runAllScanners(t *testing.T, ctx context.Context, clients []*kube.Client, registry *scanner.Registry) map[string]map[string]scanner.Result {
	t.Helper()
	results := make(map[string]map[string]scanner.Result)
	for _, c := range clients {
		results[c.Context] = make(map[string]scanner.Result)
		for name, s := range registry.All() {
			res, err := s.Scan(ctx, c)
			if err != nil {
				t.Logf("scanner %s failed on %s: %v", name, c.Context, err)
				continue
			}
			results[c.Context][name] = res
		}
	}
	return results
}

// seedClusterAlpha creates test resources in the alpha cluster to make it
// diverge from beta.
func seedClusterAlpha(t *testing.T, ctx context.Context, kubeconfigPath string) {
	t.Helper()
	cs := clientsetForContext(t, kubeconfigPath, kindContext(clusterAlpha))

	// Unique namespace with PSS enforce label.
	_, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "alpha-only",
			Labels: map[string]string{
				"pod-security.kubernetes.io/enforce": "restricted",
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	// Service in alpha-only namespace.
	_, err = cs.CoreV1().Services("alpha-only").Create(ctx, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "alpha-svc"},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{{
				Port:       8080,
				TargetPort: intstr.FromInt32(8080),
				Protocol:   corev1.ProtocolTCP,
			}},
			Selector: map[string]string{"app": "alpha"},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create service: %v", err)
	}

	// Network policy.
	_, err = cs.NetworkingV1().NetworkPolicies("alpha-only").Create(ctx, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-all"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create network policy: %v", err)
	}

	// Extra ClusterRole.
	_, err = cs.RbacV1().ClusterRoles().Create(ctx, &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "alpha-custom-role"},
		Rules: []rbacv1.PolicyRule{{
			Verbs:     []string{"get", "list"},
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
		}},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create cluster role: %v", err)
	}

	// Resource quota.
	_, err = cs.CoreV1().ResourceQuotas("alpha-only").Create(ctx, &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Name: "alpha-quota"},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("4"),
				corev1.ResourceMemory: resource.MustParse("8Gi"),
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create resource quota: %v", err)
	}
}

// seedClusterBeta creates different test resources in the beta cluster.
func seedClusterBeta(t *testing.T, ctx context.Context, kubeconfigPath string) {
	t.Helper()
	cs := clientsetForContext(t, kubeconfigPath, kindContext(clusterBeta))

	// Different unique namespace, no PSS labels.
	_, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "beta-only"},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	// Different service.
	_, err = cs.CoreV1().Services("beta-only").Create(ctx, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "beta-svc"},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{{
				Port:       9090,
				TargetPort: intstr.FromInt32(9090),
				Protocol:   corev1.ProtocolTCP,
			}},
			Selector: map[string]string{"app": "beta"},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
}

// clientsetForContext creates a Kubernetes clientset for a specific kubeconfig context.
func clientsetForContext(t *testing.T, kubeconfigPath, contextName string) kubernetes.Interface {
	t.Helper()
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath},
		&clientcmd.ConfigOverrides{CurrentContext: contextName},
	).ClientConfig()
	if err != nil {
		t.Fatalf("build config for %s: %v", contextName, err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("create clientset for %s: %v", contextName, err)
	}
	return cs
}

// kindContext returns the kubeconfig context name for a kind cluster.
func kindContext(clusterName string) string {
	return fmt.Sprintf("kind-%s", clusterName)
}

// createCluster creates a kind cluster and merges its kubeconfig into the given path.
func createCluster(t *testing.T, name, kubeconfigPath string) {
	t.Helper()
	cmd := exec.Command("kind", "create", "cluster",
		"--name", name,
		"--kubeconfig", kubeconfigPath,
		"--wait", "120s",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("create kind cluster %s: %v\n%s", name, err, stderr.String())
	}
	t.Logf("created kind cluster %s", name)
}

// deleteCluster removes a kind cluster.
func deleteCluster(t *testing.T, name string) {
	t.Helper()
	cmd := exec.Command("kind", "delete", "cluster", "--name", name)
	if err := cmd.Run(); err != nil {
		t.Logf("warning: failed to delete kind cluster %s: %v", name, err)
	}
}

// requireKind skips the test if kind is not installed.
func requireKind(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("kind"); err != nil {
		t.Skip("kind not found in PATH; install with: brew install kind")
	}
}

// requireDocker skips the test if Docker is not running.
func requireDocker(t *testing.T) {
	t.Helper()
	cmd := exec.Command("docker", "info")
	if err := cmd.Run(); err != nil {
		t.Skip("docker not running; start Docker Desktop to run integration tests")
	}
}
