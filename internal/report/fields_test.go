package report

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/scanner/admission"
	"github.com/dcadolph/fleetsweeper/internal/scanner/certs"
	"github.com/dcadolph/fleetsweeper/internal/scanner/clusterinfo"
	"github.com/dcadolph/fleetsweeper/internal/scanner/crd"
	"github.com/dcadolph/fleetsweeper/internal/scanner/deprecatedapis"
	"github.com/dcadolph/fleetsweeper/internal/scanner/events"
	"github.com/dcadolph/fleetsweeper/internal/scanner/geo"
	"github.com/dcadolph/fleetsweeper/internal/scanner/imageaudit"
	"github.com/dcadolph/fleetsweeper/internal/scanner/ingress"
	"github.com/dcadolph/fleetsweeper/internal/scanner/metrics"
	"github.com/dcadolph/fleetsweeper/internal/scanner/namespace"
	"github.com/dcadolph/fleetsweeper/internal/scanner/networkpolicy"
	"github.com/dcadolph/fleetsweeper/internal/scanner/nodehealth"
	"github.com/dcadolph/fleetsweeper/internal/scanner/policyreportingest"
	"github.com/dcadolph/fleetsweeper/internal/scanner/quota"
	"github.com/dcadolph/fleetsweeper/internal/scanner/rbac"
	"github.com/dcadolph/fleetsweeper/internal/scanner/rbacaudit"
	"github.com/dcadolph/fleetsweeper/internal/scanner/resources"
	"github.com/dcadolph/fleetsweeper/internal/scanner/security"
	"github.com/dcadolph/fleetsweeper/internal/scanner/service"
	"github.com/dcadolph/fleetsweeper/internal/scanner/version"
	"github.com/dcadolph/fleetsweeper/internal/scanner/vulnerabilities"
	"github.com/dcadolph/fleetsweeper/internal/scanner/workloadcoverage"
	"github.com/dcadolph/fleetsweeper/internal/scanner/workloadsec"
)

// testScannerData maps every registered scanner name to its data struct type.
func testScannerData() map[string]reflect.Type {
	return map[string]reflect.Type{
		admission.Name:          reflect.TypeFor[admission.Data](),
		certs.Name:              reflect.TypeFor[certs.Data](),
		clusterinfo.Name:        reflect.TypeFor[clusterinfo.Data](),
		crd.Name:                reflect.TypeFor[crd.Data](),
		deprecatedapis.Name:     reflect.TypeFor[deprecatedapis.Data](),
		events.Name:             reflect.TypeFor[events.Data](),
		geo.Name:                reflect.TypeFor[geo.Data](),
		imageaudit.Name:         reflect.TypeFor[imageaudit.Data](),
		ingress.Name:            reflect.TypeFor[ingress.Data](),
		metrics.Name:            reflect.TypeFor[metrics.Data](),
		namespace.Name:          reflect.TypeFor[namespace.Data](),
		networkpolicy.Name:      reflect.TypeFor[networkpolicy.Data](),
		nodehealth.Name:         reflect.TypeFor[nodehealth.Data](),
		policyreportingest.Name: reflect.TypeFor[policyreportingest.Data](),
		quota.Name:              reflect.TypeFor[quota.Data](),
		rbac.Name:               reflect.TypeFor[rbac.Data](),
		rbacaudit.Name:          reflect.TypeFor[rbacaudit.Data](),
		resources.Name:          reflect.TypeFor[resources.Data](),
		security.Name:           reflect.TypeFor[security.Data](),
		service.Name:            reflect.TypeFor[service.Data](),
		version.Name:            reflect.TypeFor[version.Data](),
		vulnerabilities.Name:    reflect.TypeFor[vulnerabilities.Data](),
		workloadcoverage.Name:   reflect.TypeFor[workloadcoverage.Data](),
		workloadsec.Name:        reflect.TypeFor[workloadsec.Data](),
	}
}

// testJSONFields returns the top-level JSON field names of a struct type.
func testJSONFields(t reflect.Type) map[string]struct{} {
	out := make(map[string]struct{}, t.NumField())
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			out[name] = struct{}{}
		}
	}
	return out
}

// testEmittedRules returns every rule slug a non-test source file in this package assigns
// to a finding's Rule field.
func testEmittedRules(t *testing.T) map[string]struct{} {
	t.Helper()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob sources: %v", err)
	}
	re := regexp.MustCompile(`Rule:\s+"([^"]+)"`)
	out := make(map[string]struct{})
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		for _, m := range re.FindAllSubmatch(b, -1) {
			out[string(m[1])] = struct{}{}
		}
	}
	return out
}

// TestFieldSpecsMatchScanners checks every registry entry against the scanners it names.
func TestFieldSpecsMatchScanners(t *testing.T) {
	t.Parallel()
	data := testScannerData()
	rules := testEmittedRules(t)
	seen := make(map[FieldRef]struct{}, len(fieldSpecs))
	gated := make(map[string]bool)
	for _, s := range fieldSpecs {
		t.Run(s.Scanner+"/"+s.Field, func(t *testing.T) {
			t.Parallel()
			typ, ok := data[s.Scanner]
			if !ok {
				t.Fatalf("scanner %q is not a registered scanner", s.Scanner)
			}
			fields := testJSONFields(typ)
			want := s.Field
			if s.Projection != nil {
				want = s.Projection.From
			}
			if _, ok := fields[want]; !ok {
				t.Errorf("field %q is not a json field of %s data", want, s.Scanner)
			}
			for _, r := range s.RedundantWith {
				if !DeclaredField(r.Scanner, r.Field) {
					t.Errorf("RedundantWith %s/%s has no registry entry", r.Scanner, r.Field)
				}
			}
			if s.CountedBy != "" {
				if _, ok := rules[s.CountedBy]; !ok {
					t.Errorf("CountedBy %q is not a rule any generator emits", s.CountedBy)
				}
			}
			switch s.Severity {
			case "", SeverityCritical, SeverityWarning:
			default:
				t.Errorf("Severity %q is not critical, warning, or empty", s.Severity)
			}
		})
		if _, dup := seen[s.FieldRef]; dup {
			t.Errorf("duplicate registry entry %s/%s", s.Scanner, s.Field)
		}
		seen[s.FieldRef] = struct{}{}
		if g, ok := gated[s.Scanner]; ok && g != s.AvailabilityGated {
			t.Errorf("scanner %s mixes gated and ungated entries", s.Scanner)
		}
		gated[s.Scanner] = s.AvailabilityGated
	}
}

// TestFieldSpecViews pins the tables the registry builds to their declared contents.
func TestFieldSpecViews(t *testing.T) {
	t.Parallel()
	set := func(fields ...string) map[string]struct{} {
		out := make(map[string]struct{}, len(fields))
		for _, f := range fields {
			out[f] = struct{}{}
		}
		return out
	}
	tests := []struct {
		WantResult any
		Got        any
		Name       string
	}{{ // Test 0: Critical fields.
		Name: "critical",
		Got:  criticalFields,
		WantResult: map[string]map[string]struct{}{
			"security":          set("enforced_count", "unenforced_count"),
			"network-policies":  set("namespaces_without_policies"),
			"node-health":       set("unhealthy_nodes", "memory_pressure_nodes", "not_ready_nodes"),
			"workload-security": set("privileged_containers", "host_network_pods", "host_pid_pods"),
			"rbac-audit":        set("cluster_admin_bindings", "wildcard_rules"),
		},
	}, { // Test 1: Warning fields.
		Name: "warning",
		Got:  warningFields,
		WantResult: map[string]map[string]struct{}{
			"version":         set("minor", "git_version"),
			"namespaces":      set("count"),
			"services":        set("count"),
			"crds":            set("crd_names"),
			"vulnerabilities": set("critical"),
			"policy-reports":  set("total_fail"),
			"rbac":            set("cluster_role_count", "cluster_role_binding_count"),
			"resource-quotas": set("quota_count", "namespaces_with_quotas"),
			"resources":       set("node_count", "ready_nodes", "unschedulable_nodes"),
			"node-health":     set("disk_pressure_nodes", "pid_pressure_nodes", "unschedulable_nodes"),
			"workload-security": set(
				"run_as_root_containers", "capability_additions", "allow_privilege_escalation",
			),
			"rbac-audit":  set("default_sa_bindings"),
			"image-audit": set("latest_tag", "no_digest"),
			"metrics": set(
				"avg_cpu_percent", "avg_memory_percent", "max_cpu_percent", "max_memory_percent",
			),
		},
	}, { // Test 2: Trend fields keep their order and direction.
		Name: "trend",
		Got:  trendFields,
		WantResult: []trendField{
			{"metrics", "avg_cpu_percent", true},
			{"metrics", "avg_memory_percent", true},
			{"metrics", "max_cpu_percent", true},
			{"metrics", "max_memory_percent", true},
			{"node-health", "unhealthy_nodes", true},
			{"node-health", "memory_pressure_nodes", true},
			{"node-health", "not_ready_nodes", true},
			{"events", "warning_events", true},
			{"security", "unenforced_count", true},
			{"network-policies", "namespaces_without_policies", true},
			{"resources", "unschedulable_nodes", true},
		},
	}, { // Test 3: Availability-gated scanners.
		Name:       "gated",
		Got:        availabilityGated,
		WantResult: set("vulnerabilities", "policy-reports"),
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(test.WantResult, test.Got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestSetProjectionsFromRegistry checks the projection view and the what-if refusal it drives.
func TestSetProjectionsFromRegistry(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Scanner     string
		WantFrom    string
		WantTo      string
		WantRefused bool
	}{{ // Test 0: CRDs project to names and can be rebuilt.
		Scanner: "crds", WantFrom: "crds", WantTo: "crd_names",
	}, { // Test 1: Services project to namespace/name and can be rebuilt.
		Scanner: "services", WantFrom: "services", WantTo: "service_names",
	}, { // Test 2: Ingress classes cannot be rebuilt into ingresses.
		Scanner: "ingresses", WantFrom: "ingresses", WantTo: "ingress_classes", WantRefused: true,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			p, ok := setProjections[test.Scanner]
			if !ok {
				t.Fatalf("no projection for %s", test.Scanner)
			}
			if diff := cmp.Diff(test.WantFrom+">"+test.WantTo, p.From+">"+p.To); diff != "" {
				t.Errorf("projection mismatch (-want +got):\n%s", diff)
			}
			refused := WhatIfRefusal(test.Scanner, test.WantTo) != ""
			if refused != test.WantRefused {
				t.Errorf("WhatIfRefusal refused = %v, want %v", refused, test.WantRefused)
			}
		})
	}
	if got := slices.Sorted(maps.Keys(setProjections)); len(got) != len(tests) {
		t.Errorf("setProjections has %v, want exactly the %d tested scanners", got, len(tests))
	}
}
