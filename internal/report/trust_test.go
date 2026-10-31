package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/scanner/metrics"
)

// trustResults holds scanner results per cluster, then per scanner, the shape Build takes.
type trustResults = map[string]map[string]scanner.Result

// trustFixture is one Build input the Class A trust properties run against.
type trustFixture struct {
	// Name labels the fixture in failure messages.
	Name string
	// Clusters is the cluster list passed to Build.
	Clusters []string
	// Results holds the scanner results per cluster, then per scanner.
	Results trustResults
}

// build returns the report Build makes from the fixture.
func (fx trustFixture) build() *Report {
	return Build(fx.Clusters, fx.Results)
}

// with returns a copy of the fixture named name whose results pass through edit. The copy
// shares scanner payloads, which Build never modifies.
func (fx trustFixture) with(name string, edit func(trustResults)) trustFixture {
	results := make(trustResults, len(fx.Results))
	for c, runs := range fx.Results {
		results[c] = maps.Clone(runs)
	}
	edit(results)
	return trustFixture{Name: fx.Name + "/" + name, Clusters: fx.Clusters, Results: results}
}

// trustRunKeys returns every (cluster, scanner) run in fx, sorted so failures read in order.
func trustRunKeys(fx trustFixture) []runKey {
	var keys []runKey
	for c, runs := range fx.Results {
		for s := range runs {
			keys = append(keys, runKey{scanner: s, cluster: c})
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].cluster != keys[j].cluster {
			return keys[i].cluster < keys[j].cluster
		}
		return keys[i].scanner < keys[j].scanner
	})
	return keys
}

// trustErrored returns an errored result for name, the shape a forbidden read produces.
func trustErrored(name string) scanner.Result {
	return scanner.ErroredResult(name, errors.New("forbidden"))
}

// trustCleanRuns returns a full set of OK scanner runs for one cluster that raises no finding.
// Every cluster gets the same values, so no field is a fleet outlier.
func trustCleanRuns() map[string]scanner.Result {
	return map[string]scanner.Result{
		"version":     okRun("version", map[string]any{"git_version": "v1.31.2", "minor": "31"}),
		"namespaces":  okRun("namespaces", map[string]any{"count": 8}),
		"node-health": okRun("node-health", map[string]any{"node_count": 5, "healthy_nodes": 5}),
		"metrics": okRun("metrics", map[string]any{
			"available": true, "node_count": 5, "nodes_with_usage": 5,
			"avg_cpu_percent": 35.0, "avg_memory_percent": 45.0,
			"max_cpu_percent": 50.0, "max_memory_percent": 60.0,
		}),
		"events": okRun("events", map[string]any{
			"warning_events": 0, "top_warning_reasons": []any{},
		}),
		"resource-quotas": okRun("resource-quotas", map[string]any{"namespaces_with_quotas": 3}),
		"security": okRun("security", map[string]any{
			"namespace_count": 8, "enforced_count": 8, "unenforced_count": 0,
		}),
		"network-policies": okRun("network-policies", map[string]any{
			"count": 10, "namespaces_with_policies": 8, "namespaces_without_policies": 0,
		}),
		"workload-security": okRun("workload-security", map[string]any{
			"total_pods": 40, "privileged_containers": 0, "host_network_pods": 0,
			"host_pid_pods": 0, "run_as_root_containers": 0, "capability_additions": 0,
		}),
		"rbac-audit": okRun("rbac-audit", map[string]any{
			"cluster_admin_bindings": 0, "wildcard_rules": 0, "default_sa_bindings": 0,
		}),
		"image-audit": okRun("image-audit", map[string]any{
			"total_containers": 50, "latest_tag": 0, "no_digest": 0,
		}),
		"workload-coverage": okRun("workload-coverage", map[string]any{"gaps": []any{}}),
		"certs":             okRun("certs", map[string]any{"certs": []any{}}),
		"admission":         okRun("admission", map[string]any{"webhooks": []any{}}),
		"deprecated-apis":   okRun("deprecated-apis", map[string]any{"deprecated": []any{}}),
		"cluster-info":      okRun("cluster-info", map[string]any{"has_drift": false}),
	}
}

// trustFleet returns a fixture of the named clusters, each with trustCleanRuns, then applies
// quirks: per cluster, per scanner, the fields that replace the clean payload's.
func trustFleet(name string, clusters []string, quirks map[string]map[string]map[string]any) trustFixture {
	results := make(trustResults, len(clusters))
	for _, c := range clusters {
		runs := trustCleanRuns()
		for s, fields := range quirks[c] {
			data := maps.Clone(runs[s].Data.(map[string]any))
			maps.Copy(data, fields)
			runs[s] = okRun(s, data)
		}
		results[c] = runs
	}
	return trustFixture{Name: name, Clusters: clusters, Results: results}
}

// trustTenClusters names the clusters of the synthetic ten-cluster fleet.
func trustTenClusters() []string {
	out := make([]string, 10)
	for i := range out {
		out[i] = fmt.Sprintf("c%02d", i)
	}
	return out
}

// trustFixtures returns the fixtures every property runs on: the three-cluster sample shape,
// a ten-cluster fleet with one finding per rule family, the same fleet with no findings at
// all, and a ten-cluster fleet already ungraded by one blind cluster.
func trustFixtures() []trustFixture {
	ten := trustTenClusters()
	findings := trustFleet("ten-findings", ten, map[string]map[string]map[string]any{
		"c00": {"workload-coverage": {"gaps": []any{map[string]any{
			"namespace": "app", "name": "api", "kind": "Deployment", "has_pdb": false, "has_hpa": true,
		}}}},
		"c01": {"image-audit": {"no_digest": 10}},
		"c02": {"rbac-audit": {"wildcard_rules": 1}},
		"c03": {"node-health": {"memory_pressure_nodes": 1, "healthy_nodes": 4}},
		"c04": {"events": {"warning_events": 40, "top_warning_reasons": []any{
			map[string]any{"reason": "OOMKilling", "count": 4},
		}}},
		"c05": {"resource-quotas": {"namespaces_with_quotas": 0}},
		"c06": {"security": {"unenforced_count": 2, "enforced_count": 6}},
		"c07": {"network-policies": {"namespaces_without_policies": 3, "namespaces_with_policies": 5}},
		"c08": {"workload-security": {"privileged_containers": 1}},
		"c09": {"version": {"git_version": "v1.30.4", "minor": "30"}},
	})
	sample := trustFleet("sample", []string{"prod-us-east", "prod-us-west", "staging-eu"},
		map[string]map[string]map[string]any{
			"prod-us-east": {"metrics": {"avg_cpu_percent": 42.3, "avg_memory_percent": 58.1}},
			"prod-us-west": {"security": {"unenforced_count": 1, "enforced_count": 7}},
			"staging-eu": {
				"version":         {"git_version": "v1.30.6", "minor": "30"},
				"resource-quotas": {"namespaces_with_quotas": 0},
			},
		})
	clean := trustFleet("ten-clean", ten, nil)
	blind := clean.with("one-blind-cluster", func(res trustResults) {
		for s := range res["c00"] {
			res["c00"][s] = trustErrored(s)
		}
	})
	return []trustFixture{sample, findings, clean, blind}
}

// trustVariants returns fx and the degraded views of it the properties must hold over: every
// single run errored, every scanner errored fleet-wide, every cluster fully errored, every run
// missing, and metrics degraded with no node percentages on every cluster.
func trustVariants(fx trustFixture) []trustFixture {
	keys := trustRunKeys(fx)
	out := make([]trustFixture, 0, 1+2*len(keys)+len(fx.Results)+2*len(fx.Clusters))
	out = append(out, fx)
	for _, k := range keys {
		out = append(out,
			fx.with("errored "+k.cluster+"/"+k.scanner, func(res trustResults) {
				res[k.cluster][k.scanner] = trustErrored(k.scanner)
			}),
			fx.with("absent "+k.cluster+"/"+k.scanner, func(res trustResults) {
				delete(res[k.cluster], k.scanner)
			}),
		)
	}
	for _, s := range scanner.Names(fx.Results) {
		out = append(out, fx.with("errored fleet-wide "+s, func(res trustResults) {
			for c := range res {
				res[c][s] = trustErrored(s)
			}
		}))
	}
	for _, c := range fx.Clusters {
		out = append(out,
			fx.with("blind cluster "+c, func(res trustResults) {
				for s := range res[c] {
					res[c][s] = trustErrored(s)
				}
			}),
			fx.with("metrics without usage "+c, func(res trustResults) {
				res[c]["metrics"] = scanner.Result{
					Scanner: "metrics", State: scanner.StateDegraded, Reason: "nodes forbidden",
					Data: metrics.Data{Available: true, NodeCount: 5},
				}
			}),
		)
	}
	return out
}

// briefText joins a brief's headline and lines so a sentence can be found anywhere in it.
func briefText(b Brief) string {
	return strings.Join(append([]string{b.Headline}, b.Lines...), "\n")
}

// decodeReport returns r after a JSON round trip, rescored and rebriefed the way a stored
// report is read back, so properties hold for decoded reports as well as built ones.
func decodeReport(t *testing.T, r *Report) *Report {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	var out Report
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	Rescore(&out)
	out.Brief = generateBrief(&out)
	return &out
}

// TestTrustNoObservedRunsUngraded pins P1: a report in which no scanner run observed the fleet
// is never graded, and its headline and brief both start "Not enough data", built or decoded.
func TestTrustNoObservedRunsUngraded(t *testing.T) {
	t.Parallel()
	clean := trustFleet("ten-clean", trustTenClusters(), nil)
	tests := []struct {
		Fixture trustFixture
	}{{ // Test 0: Every run on every cluster errored.
		Fixture: clean.with("all errored", func(res trustResults) {
			for c := range res {
				for s := range res[c] {
					res[c][s] = trustErrored(s)
				}
			}
		}),
	}, { // Test 1: Clusters are listed but no scanner ran on any of them.
		Fixture: trustFixture{Name: "no runs", Clusters: trustTenClusters()},
	}, { // Test 2: Every run degraded, so none completed.
		Fixture: clean.with("all degraded", func(res trustResults) {
			for c := range res {
				for s, run := range res[c] {
					res[c][s] = degradedRun(s, run.Data.(map[string]any))
				}
			}
		}),
	}, { // Test 3: A single-cluster fleet whose only runs errored.
		Fixture: trustFixture{Name: "one cluster", Clusters: []string{"solo"},
			Results: trustResults{"solo": {
				"metrics": trustErrored("metrics"), "node-health": trustErrored("node-health"),
			}}},
	}, { // Test 4: Metrics degraded and every other run errored.
		Fixture: clean.with("errored and degraded", func(res trustResults) {
			for c := range res {
				for s, run := range res[c] {
					if s == "metrics" {
						res[c][s] = degradedRun(s, run.Data.(map[string]any))
						continue
					}
					res[c][s] = trustErrored(s)
				}
			}
		}),
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			built := test.Fixture.build()
			for label, r := range map[string]*Report{"built": built, "decoded": decodeReport(t, built)} {
				fs := r.FleetScore
				if diff := cmp.Diff(0, fs.Coverage.ObservedRuns); diff != "" {
					t.Fatalf("%s: fixture observes runs (-want +got):\n%s", label, diff)
				}
				if fs.Graded || fs.Grade != "" {
					t.Errorf("%s: graded %v with grade %q on zero observed runs", label, fs.Graded, fs.Grade)
				}
				if !strings.HasPrefix(fs.Headline, "Not enough data") {
					t.Errorf("%s: headline %q does not start %q", label, fs.Headline, "Not enough data")
				}
				if !strings.HasPrefix(r.Brief.Headline, "Not enough data") {
					t.Errorf("%s: brief %q does not start %q", label, r.Brief.Headline, "Not enough data")
				}
			}
		})
	}
}

// TestTrustBlindRunsNeverClaimNoDrift pins P2: whenever a run went blind, the headline never
// says "no meaningful drift" and both the headline and the brief carry the coverage sentence.
// It fails if no variant reaches the top score band with a blind run, since then it proves
// nothing about the claim it guards.
func TestTrustBlindRunsNeverClaimNoDrift(t *testing.T) {
	t.Parallel()
	var topBand, blind int
	for _, fx := range trustFixtures() {
		for _, v := range trustVariants(fx) {
			r := v.build()
			fs := r.FleetScore
			if fs.Coverage.BlindRuns == 0 {
				continue
			}
			blind++
			if fs.Score >= 95 {
				topBand++
			}
			if strings.Contains(fs.Headline, "no meaningful drift") {
				t.Errorf("%s: headline %q claims no drift with %d blind runs",
					v.Name, fs.Headline, fs.Coverage.BlindRuns)
			}
			sentence := coverageSentence(fs.Coverage, len(r.Clusters))
			if sentence == "" {
				t.Errorf("%s: no coverage sentence for %d blind runs", v.Name, fs.Coverage.BlindRuns)
				continue
			}
			if !strings.Contains(fs.Headline, sentence) {
				t.Errorf("%s: headline %q lacks %q", v.Name, fs.Headline, sentence)
			}
			if !strings.Contains(briefText(r.Brief), sentence) {
				t.Errorf("%s: brief %q lacks %q", v.Name, briefText(r.Brief), sentence)
			}
		}
	}
	if blind == 0 || topBand == 0 {
		t.Fatalf("vacuous: %d blind variants, %d in the top band", blind, topBand)
	}
}

// trustClusterView is what one cluster reads as in a built report.
type trustClusterView struct {
	// Status is the cluster health status.
	Status string
	// Raw is the fleet ledger's precap cost charged to the cluster, which no other cluster's
	// findings can scale.
	Raw float64
	// Score is the cluster's own score.
	Score int
}

// trustViewOf returns how cluster reads in r.
func trustViewOf(r *Report, cluster string) trustClusterView {
	var v trustClusterView
	for _, e := range r.ScoreAttribution.Entries {
		if e.Cluster == cluster {
			v.Raw += e.Raw
		}
	}
	for _, h := range r.ClusterHealths {
		if h.Name == cluster {
			v.Status = h.Status
			v.Score = ComputeClusterScore(h, r.Findings).Score
		}
	}
	return v
}

// TestTrustErroredRunNeverHelps pins P3: replacing any OK run with an errored one never reads
// better than a clean observation of that run, which is the fixture with the run's payload
// swapped for the finding-free one. The errored run never grades a report the observation left
// ungraded, drops exactly one observed run, and never leaves its cluster healthy. Where the
// observation leaves the cluster healthy, the errored run lowers the cluster's score and never
// lowers its ledger cost. On the fleet with no findings it never raises the fleet score. The
// fleet score is not compared elsewhere: the design never charges a blind run as if its worst
// finding were present, so a forbidden read that hides a real finding may lower the cost.
func TestTrustErroredRunNeverHelps(t *testing.T) { //nolint:funlen // Test function.
	t.Parallel()
	var healthy int
	for _, fx := range trustFixtures() {
		base := fx.build()
		noFindings := len(base.Findings) == 0
		for _, k := range trustRunKeys(fx) {
			if fx.Results[k.cluster][k.scanner].State != scanner.StateOK {
				continue
			}
			clean := fx.with("clean "+k.cluster+"/"+k.scanner, func(res trustResults) {
				res[k.cluster][k.scanner] = trustCleanRuns()[k.scanner]
			}).build()
			blindFx := fx.with("errored "+k.cluster+"/"+k.scanner, func(res trustResults) {
				res[k.cluster][k.scanner] = trustErrored(k.scanner)
			})
			blind := blindFx.build()
			name := blindFx.Name
			if blind.FleetScore.Graded && (!clean.FleetScore.Graded || !base.FleetScore.Graded) {
				t.Errorf("%s: an errored run graded a report its observation left ungraded", name)
			}
			if diff := cmp.Diff(clean.FleetScore.Coverage.ObservedRuns-1,
				blind.FleetScore.Coverage.ObservedRuns); diff != "" {
				t.Errorf("%s: observed runs mismatch (-want +got):\n%s", name, diff)
			}
			want, got := trustViewOf(clean, k.cluster), trustViewOf(blind, k.cluster)
			if got.Status == "healthy" {
				t.Errorf("%s: cluster reads healthy with an errored run", name)
			}
			if want.Status == "healthy" {
				healthy++
				if got.Score >= want.Score {
					t.Errorf("%s: cluster scores %d, observed it scores %d", name, got.Score, want.Score)
				}
				if got.Raw < want.Raw {
					t.Errorf("%s: cluster costs %.2f, observed it costs %.2f", name, got.Raw, want.Raw)
				}
			}
			if noFindings && blind.FleetScore.Score > base.FleetScore.Score {
				t.Errorf("%s: fleet score rose from %d to %d", name,
					base.FleetScore.Score, blind.FleetScore.Score)
			}
		}
	}
	if healthy == 0 {
		t.Fatal("vacuous: no errored run replaced one on a cluster its observation left healthy")
	}
}

// TestTrustAbsenceRulesNeedCompleteRun pins P4: each absence rule claims a missing control only
// from a completed run. An errored or degraded run on one cluster of the ten-cluster fleet
// leaves that cluster without the finding in the built report, while the completed run raises
// it. The no-digest rule counts containers it saw unpinned, so it is a presence rule (unit A2):
// a degraded run may raise it but must say the scan was partial.
func TestTrustAbsenceRulesNeedCompleteRun(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Data         map[string]any
		Scanner      string
		Rule         string
		WantDegraded int
	}{{ // Test 0: No resource quotas with live namespaces (R-5).
		Scanner: "resource-quotas", Rule: "resource-quotas/no-quota",
		Data: map[string]any{"namespaces_with_quotas": 0},
	}, { // Test 1: Namespaces without a network policy.
		Scanner: "network-policies", Rule: "network-policies/no-policy",
		Data: map[string]any{"count": 0, "namespaces_with_policies": 0, "namespaces_without_policies": 8},
	}, { // Test 2: Every namespace without Pod Security enforcement.
		Scanner: "security", Rule: "security/psa-unenforced",
		Data: map[string]any{"namespace_count": 8, "enforced_count": 0, "unenforced_count": 8},
	}, { // Test 3: Images without digest pins, a presence count marked partial when degraded.
		Scanner: "image-audit", Rule: "image-audit/no-digest", WantDegraded: 1,
		Data: map[string]any{"total_containers": 50, "latest_tag": 0, "no_digest": 50},
	}, { // Test 4: A replicated workload without a PodDisruptionBudget.
		Scanner: "workload-coverage", Rule: "workload-coverage/missing-pdb",
		Data: map[string]any{"gaps": []any{map[string]any{
			"namespace": "app", "name": "api", "kind": "Deployment", "has_pdb": false, "has_hpa": true,
		}}},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			clean := trustFleet("ten-clean", trustTenClusters(), nil)
			runs := map[string]scanner.Result{
				"ok":       okRun(test.Scanner, test.Data),
				"degraded": degradedRun(test.Scanner, test.Data),
				"errored":  trustErrored(test.Scanner),
			}
			want := map[string]int{"ok": 1, "degraded": test.WantDegraded, "errored": 0}
			for state, run := range runs {
				r := clean.with(state, func(res trustResults) {
					res["c03"][test.Scanner] = run
				}).build()
				var got []Finding
				for _, f := range findingsWithRule(r.Findings, test.Rule) {
					if f.Cluster == "c03" {
						got = append(got, f)
					}
				}
				if diff := cmp.Diff(want[state], len(got)); diff != "" {
					t.Errorf("%s run finding count mismatch (-want +got):\n%s", state, diff)
				}
				for _, f := range got {
					if state == "degraded" && !strings.Contains(f.Description, partialScanNote) {
						t.Errorf("degraded run finding %q is not marked partial", f.Description)
					}
				}
			}
		})
	}
}

// TestTrustNoHeadroomWithoutMetrics pins P5: across every fixture variant, a capacity entry
// carries a utilization or headroom figure only when the metrics run observed both averages,
// and a cluster whose metrics went unobserved never gets one.
func TestTrustNoHeadroomWithoutMetrics(t *testing.T) {
	t.Parallel()
	var unobserved int
	for _, fx := range trustFixtures() {
		for _, v := range trustVariants(fx) {
			r := v.build()
			for _, ca := range r.Capacity {
				_, cpuObs := observe(r, "metrics", ca.Cluster, "avg_cpu_percent")
				_, memObs := observe(r, "metrics", ca.Cluster, "avg_memory_percent")
				if weakest(cpuObs, memObs).seen() {
					continue
				}
				unobserved++
				if ca.HeadroomCPU != nil || ca.HeadroomMemory != nil ||
					ca.CPUUtilization != nil || ca.MemoryUtilization != nil {
					t.Errorf("%s: %s has a figure without observed metrics: headroom cpu %v mem %v",
						v.Name, ca.Cluster, ca.HeadroomCPU, ca.HeadroomMemory)
				}
				if ca.Status != capacityUnknown && ca.Status != capacityStrained &&
					ca.Status != capacityCritical {
					t.Errorf("%s: %s reads %q without observed metrics", v.Name, ca.Cluster, ca.Status)
				}
			}
		}
	}
	if unobserved == 0 {
		t.Fatal("vacuous: no variant left a cluster's metrics unobserved")
	}
}
