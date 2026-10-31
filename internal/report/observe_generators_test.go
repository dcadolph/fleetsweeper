package report

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// TestGeneratorCoverage checks each converted generator against an errored, degraded, and
// completed run. Absence rules stay silent unless the run completed. Presence rules fire on a
// degraded run and mark the description partial.
func TestGeneratorCoverage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Gen     func(*Report) []Finding
		Data    map[string]any
		Scanner string
		Rule    string
		Absence bool
	}{{ // Test 0: Unenforced namespaces are a presence rule.
		Gen: securityFindings, Scanner: "security", Rule: "security/psa-unenforced",
		Data: map[string]any{"unenforced_count": 2, "namespace_count": 5},
	}, { // Test 1: Every namespace unenforced is an absence claim.
		Gen: securityFindings, Scanner: "security", Rule: "security/psa-unenforced", Absence: true,
		Data: map[string]any{"unenforced_count": 5, "namespace_count": 5},
	}, { // Test 2: Namespaces without network policies is an absence rule.
		Gen: networkFindings, Scanner: "network-policies", Rule: "network-policies/no-policy",
		Absence: true, Data: map[string]any{"namespaces_without_policies": 2},
	}, { // Test 3: Privileged containers are a presence rule.
		Gen: workloadSecFindings, Scanner: "workload-security", Rule: "workload-security/privileged",
		Data: map[string]any{"privileged_containers": 1, "total_pods": 4},
	}, { // Test 4: Host namespaces are a presence rule.
		Gen: workloadSecFindings, Scanner: "workload-security",
		Rule: "workload-security/host-namespaces",
		Data: map[string]any{"host_network_pods": 1, "host_pid_pods": 0, "total_pods": 4},
	}, { // Test 5: Root containers are a presence rule.
		Gen: workloadSecFindings, Scanner: "workload-security", Rule: "workload-security/run-as-root",
		Data: map[string]any{"run_as_root_containers": 1, "total_pods": 4},
	}, { // Test 6: Added capabilities are a presence rule.
		Gen: workloadSecFindings, Scanner: "workload-security",
		Rule: "workload-security/capability-add",
		Data: map[string]any{"capability_additions": 1, "total_pods": 4},
	}, { // Test 7: Cluster-admin bindings are a presence rule.
		Gen: rbacAuditFindings, Scanner: "rbac-audit", Rule: "rbac-audit/cluster-admin-binding",
		Data: map[string]any{"cluster_admin_bindings": 1},
	}, { // Test 8: Wildcard rules are a presence rule.
		Gen: rbacAuditFindings, Scanner: "rbac-audit", Rule: "rbac-audit/wildcard-rule",
		Data: map[string]any{"wildcard_rules": 1},
	}, { // Test 9: Default service account bindings are a presence rule.
		Gen: rbacAuditFindings, Scanner: "rbac-audit", Rule: "rbac-audit/default-sa-binding",
		Data: map[string]any{"default_sa_bindings": 1},
	}, { // Test 10: Expiring certificates are a presence rule.
		Gen: certFindings, Scanner: "certs", Rule: "certs/expiring-7d",
		Data: map[string]any{"certs": []any{map[string]any{"name": "a", "days_remaining": 3}}},
	}, { // Test 11: Unhealthy webhooks are a presence rule.
		Gen: admissionFindings, Scanner: "admission", Rule: "admission/no-healthy-endpoints",
		Data: map[string]any{"webhooks": []any{map[string]any{
			"configuration": "c", "webhook": "w", "service": "ns/svc", "ca_bundle_days_remaining": 90,
		}}},
	}, { // Test 12: Latest-tag images are a presence rule.
		Gen: imageAuditFindings, Scanner: "image-audit", Rule: "image-audit/latest-tag",
		Data: map[string]any{"latest_tag": 2, "total_containers": 10},
	}, { // Test 13: Images without digests are a presence rule.
		Gen: imageAuditFindings, Scanner: "image-audit", Rule: "image-audit/no-digest",
		Data: map[string]any{"no_digest": 2, "total_containers": 10},
	}, { // Test 14: A missing PDB is an absence rule.
		Gen: coverageFindings, Scanner: "workload-coverage", Rule: "workload-coverage/missing-pdb",
		Absence: true, Data: map[string]any{"gaps": []any{map[string]any{
			"namespace": "ns", "name": "app", "kind": "Deployment", "has_pdb": false, "has_hpa": true,
		}}},
	}, { // Test 15: A missing HPA is an absence rule.
		Gen: coverageFindings, Scanner: "workload-coverage", Rule: "workload-coverage/missing-hpa",
		Absence: true, Data: map[string]any{"gaps": []any{map[string]any{
			"namespace": "ns", "name": "app", "kind": "Deployment", "has_pdb": true, "has_hpa": false,
		}}},
	}, { // Test 16: Deprecated APIs are a presence rule.
		Gen: deprecatedAPIFindings, Scanner: "deprecated-apis", Rule: "deprecated-apis/in-use",
		Data: map[string]any{"deprecated": []any{map[string]any{"api_version": "v1beta1", "kind": "X"}}},
	}, { // Test 17: Node platform drift is a presence rule.
		Gen: clusterInfoFindings, Scanner: "cluster-info", Rule: "cluster-info/node-platform-drift",
		Data: map[string]any{"has_drift": true},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			runs := map[string]scanner.Result{
				"errored":  erroredRun(test.Scanner),
				"degraded": degradedRun(test.Scanner, test.Data),
				"ok":       okRun(test.Scanner, test.Data),
			}
			wantCount := map[string]int{"errored": 0, "degraded": 1, "ok": 1}
			if test.Absence {
				wantCount["degraded"] = 0
			}
			for name, run := range runs {
				r := Build([]string{"c1"}, map[string]map[string]scanner.Result{
					"c1": {test.Scanner: run},
				})
				got := findingsWithRule(test.Gen(r), test.Rule)
				if diff := cmp.Diff(wantCount[name], len(got)); diff != "" {
					t.Fatalf("%s finding count mismatch (-want +got):\n%s", name, diff)
				}
				if len(got) == 0 {
					continue
				}
				gotPartial := strings.HasSuffix(got[0].Description, partialScanNote)
				if diff := cmp.Diff(name == "degraded", gotPartial); diff != "" {
					t.Errorf("%s partial note mismatch (-want +got):\n%s", name, diff)
				}
			}
		})
	}
}

// TestVersionFindingsCoverage leaves clusters without an observed version out of the skew set.
func TestVersionFindingsCoverage(t *testing.T) {
	t.Parallel()
	ver := func(v string) scanner.Result {
		return okRun("version", map[string]any{"git_version": v})
	}
	tests := []struct {
		Third        scanner.Result
		WantAffected []string
		WantCount    int
	}{{ // Test 0: An errored third cluster is not a distinct version.
		Third: erroredRun("version"), WantCount: 1, WantAffected: []string{"c1=v1.28.0", "c2=v1.30.0"},
	}, { // Test 1: A degraded third cluster still read its version, so it joins the skew set.
		Third:     degradedRun("version", map[string]any{"git_version": "v1.20.0"}),
		WantCount: 1, WantAffected: []string{"c1=v1.28.0", "c2=v1.30.0", "c3=v1.20.0"},
	}, { // Test 2: A completed third cluster joins the skew set.
		Third: ver("v1.20.0"), WantCount: 1,
		WantAffected: []string{"c1=v1.28.0", "c2=v1.30.0", "c3=v1.20.0"},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			r := Build([]string{"c1", "c2", "c3"}, map[string]map[string]scanner.Result{
				"c1": {"version": ver("v1.28.0")},
				"c2": {"version": ver("v1.30.0")},
				"c3": {"version": test.Third},
			})
			got := versionFindings(r)
			if diff := cmp.Diff(test.WantCount, len(got)); diff != "" {
				t.Fatalf("finding count mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantAffected, got[0].Affected); diff != "" {
				t.Errorf("affected mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestNamespaceFindingsCoverage leaves unobserved clusters out of the namespace comparison.
func TestNamespaceFindingsCoverage(t *testing.T) {
	t.Parallel()
	ns := func(n int) scanner.Result { return okRun("namespaces", map[string]any{"count": n}) }
	tests := []struct {
		Third     scanner.Result
		WantCount int
	}{{ // Test 0: An errored cluster is not compared as zero namespaces.
		Third: erroredRun("namespaces"), WantCount: 0,
	}, { // Test 1: A completed cluster with zero namespaces is compared.
		Third: ns(0), WantCount: 1,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			r := Build([]string{"c1", "c2", "c3"}, map[string]map[string]scanner.Result{
				"c1": {"namespaces": ns(5)},
				"c2": {"namespaces": ns(6)},
				"c3": {"namespaces": test.Third},
			})
			if diff := cmp.Diff(test.WantCount, len(namespaceFindings(r))); diff != "" {
				t.Errorf("finding count mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
