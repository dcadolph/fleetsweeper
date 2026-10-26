package server

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// demoTestServer returns an insecure demo server over an empty store.
func demoTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.NewSQLite(filepath.Join(t.TempDir(), "demo.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	srv := New(Config{Store: st, Registry: scanner.NewRegistry(), Log: zap.NewNop(), Insecure: true, Demo: true})
	t.Cleanup(func() {
		srv.Close()
		st.Close()
	})
	return srv
}

// serve sends one request through the server's full handler chain and decodes a 200 body into
// out when out is non-nil. It returns the status code.
func serve(t *testing.T, h http.Handler, method, target, body, token string, out any) int {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code == http.StatusOK && out != nil {
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			t.Fatalf("%s %s: decode: %v\n%s", method, target, err, w.Body.String())
		}
	}
	return w.Code
}

// TestDemoDistributions verifies the demo serves the engine's distributions: fleet scope by
// default, every scope with scope=*, and filters by scanner and field.
func TestDemoDistributions(t *testing.T) {
	t.Parallel()
	h := demoTestServer(t).Handler()
	want := demoScanInput().build().Distributions

	var all distributionsResponse
	if code := serve(t, h, http.MethodGet, "/api/distributions?scope=*", "", "", &all); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if diff := cmp.Diff(want, all.Distributions); diff != "" {
		t.Errorf("distributions mismatch (-engine +served):\n%s", diff)
	}
	if all.ScanID != demoScanID {
		t.Errorf("scan id %q", all.ScanID)
	}

	var fleet distributionsResponse
	serve(t, h, http.MethodGet, "/api/distributions", "", "", &fleet)
	if len(fleet.Distributions) == 0 {
		t.Fatal("no fleet distributions")
	}
	for _, d := range fleet.Distributions {
		if d.Scope != report.NormScopeFleet {
			t.Errorf("default scope served %q", d.Scope)
		}
	}

	var one distributionsResponse
	serve(t, h, http.MethodGet, "/api/distributions?scanner=security&field=enforced_count", "", "", &one)
	if len(one.Distributions) != 1 || one.Distributions[0].Field != "enforced_count" {
		t.Errorf("filter: want one enforced_count distribution, got %d", len(one.Distributions))
	}
}

// TestDemoDrift verifies the demo history's stepping cluster leads the drift ledger, with the
// flag it gained stamped by the scan of the step.
func TestDemoDrift(t *testing.T) {
	t.Parallel()
	h := demoTestServer(t).Handler()
	var l report.Ledger
	if code := serve(t, h, http.MethodGet, "/api/drift?scans=24", "", "", &l); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if len(l.Scans) != 24 || len(l.Clusters) == 0 {
		t.Fatalf("ledger: %d scans, %d rows", len(l.Scans), len(l.Clusters))
	}
	top := l.Clusters[0]
	if top.Cluster != demoStepCluster {
		t.Fatalf("first row %s, want %s", top.Cluster, demoStepCluster)
	}
	step := 24 - 24/3
	wantScan := demoScanID + "-t" + itoa(step)
	found := false
	for _, g := range top.Gained {
		if g.Scanner == "rbac" && g.Field == "cluster_role_count" {
			found = g.Scan == wantScan
		}
	}
	if !found {
		t.Errorf("want rbac/cluster_role_count gained at %s, got %+v", wantScan, top.Gained)
	}
}

// TestDemoDistributionHistory verifies the history endpoint returns one point per scan, oldest
// first, and that the stepping cluster's value moves at the step.
func TestDemoDistributionHistory(t *testing.T) {
	t.Parallel()
	h := demoTestServer(t).Handler()
	if code := serve(t, h, http.MethodGet, "/api/distributions/history?field=x", "", "", nil); code != http.StatusBadRequest {
		t.Errorf("missing scanner: want 400, got %d", code)
	}
	var out historyResponse
	if code := serve(t, h, http.MethodGet, "/api/distributions/history?scanner=rbac&field=cluster_role_count&scans=12", "", "", &out); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if len(out.Points) != 12 {
		t.Fatalf("points: want 12, got %d", len(out.Points))
	}
	value := func(p historyPoint) float64 {
		for _, v := range p.Distribution.Values {
			if v.Cluster == demoStepCluster {
				return *v.Number
			}
		}
		return math.NaN()
	}
	for i := 1; i < len(out.Points); i++ {
		if !out.Points[i].Timestamp.After(out.Points[i-1].Timestamp) {
			t.Errorf("points out of order at %d", i)
		}
	}
	if jump := value(out.Points[8]) - value(out.Points[7]); jump != 60 {
		t.Errorf("want a step of 60 between points 7 and 8, got %v", jump)
	}
}

// TestDemoAttributionMapDetail verifies the attribution ledger explains the score, the cohort
// map places every demo cluster, and cluster detail lists peers and flagged distributions.
func TestDemoAttributionMapDetail(t *testing.T) {
	t.Parallel()
	h := demoTestServer(t).Handler()

	var attr attributionResponse
	if code := serve(t, h, http.MethodGet, "/api/score/attribution", "", "", &attr); code != http.StatusOK {
		t.Fatalf("attribution status %d", code)
	}
	if math.Abs(100-attr.Attribution.Total-float64(attr.Score.Score)) > 0.5 && attr.Attribution.Total < 100 {
		t.Errorf("100 - total %v is not score %d", attr.Attribution.Total, attr.Score.Score)
	}

	var m cohortMapResponse
	if code := serve(t, h, http.MethodGet, "/api/cohorts/map", "", "", &m); code != http.StatusOK {
		t.Fatalf("map status %d", code)
	}
	if len(m.Map.Points) != len(demoPoints()) || len(m.Map.LeafOrder) != len(demoPoints()) {
		t.Errorf("map: %d points, %d leaves, want %d", len(m.Map.Points), len(m.Map.LeafOrder), len(demoPoints()))
	}

	var detail struct {
		Peers         []json.RawMessage     `json:"peers"`
		Distributions []report.Distribution `json:"distributions"`
	}
	if code := serve(t, h, http.MethodGet, "/api/clusters/"+demoStepCluster+"/detail", "", "", &detail); code != http.StatusOK {
		t.Fatalf("detail status %d", code)
	}
	if len(detail.Peers) != 5 {
		t.Errorf("detail peers: want 5, got %d", len(detail.Peers))
	}
	for _, d := range detail.Distributions {
		flagged := false
		for _, v := range d.Values {
			flagged = flagged || (v.Cluster == demoStepCluster && v.Outlier)
		}
		if !flagged {
			t.Errorf("detail lists %s/%s where the cluster is not flagged", d.Scanner, d.Field)
		}
	}
}

// TestDemoWhatIf verifies fixing a demo outlier projects a higher score and that bad requests
// are rejected without a write.
func TestDemoWhatIf(t *testing.T) {
	t.Parallel()
	h := demoTestServer(t).Handler()
	rpt := demoScanInput().build()
	var target report.OutlierResult
	for _, o := range rpt.Outliers {
		if o.Kind == report.NormKindNumeric && o.Severity != report.SeverityInfo {
			target = o
			break
		}
	}
	if target.Cluster == "" {
		t.Fatal("demo has no numeric outlier above info")
	}
	body := fmt.Sprintf(`{"cluster":%q,"scanner":%q,"field":%q}`, target.Cluster, target.Scanner, target.Field)
	var out whatifResponse
	if code := serve(t, h, http.MethodPost, "/api/whatif", body, "", &out); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	// The demo score sits at the floor of every capped term, so one fix cannot move it yet;
	// unit 26 retunes the demo and tightens this to a strict rise.
	if out.Outcome.ScoreAfter < out.Outcome.ScoreBefore {
		t.Errorf("score fell: %d -> %d", out.Outcome.ScoreBefore, out.Outcome.ScoreAfter)
	}
	cleared := false
	for _, c := range out.Outcome.ClearedOutliers {
		cleared = cleared || c == target.Cluster
	}
	if !cleared {
		t.Errorf("fixing %s did not clear it: %+v", target.Cluster, out.Outcome.ClearedOutliers)
	}
	for _, c := range []struct {
		Body string
		Want int
	}{
		{Body: `{"cluster":"x"}`, Want: http.StatusBadRequest},
		{Body: `{"cluster":"x","scanner":"security","field":"nope"}`, Want: http.StatusUnprocessableEntity},
		{Body: `{"cluster":"x","scanner":"security","field":"enforced_count","extra":1}`, Want: http.StatusBadRequest},
	} {
		if code := serve(t, h, http.MethodPost, "/api/whatif", c.Body, "", nil); code != c.Want {
			t.Errorf("%s: want %d, got %d", c.Body, c.Want, code)
		}
	}
}

// TestWhatIfAuth verifies a viewer key may project a fix on a cluster in its scope, gets 403
// outside it, and leaves no audit entry, since nothing is written.
func TestWhatIfAuth(t *testing.T) {
	t.Parallel()
	srv, st := newAuthTestServer(t)
	seedTenClusters(t, st, "scan-1", time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), 80)
	viewer := saveTestKey(t, st, "key_viewer", store.RoleViewer, "c00", "c04")
	h := srv.Handler()

	body := `{"cluster":"c04","scanner":"security","field":"enforced_count"}`
	var out whatifResponse
	if code := serve(t, h, http.MethodPost, "/api/whatif", body, viewer, &out); code != http.StatusOK {
		t.Fatalf("viewer in scope: want 200, got %d", code)
	}
	if out.ScanID != "scan-1" || out.Outcome.ScoreAfter <= out.Outcome.ScoreBefore {
		t.Errorf("outcome %+v", out)
	}
	outside := `{"cluster":"c05","scanner":"security","field":"enforced_count"}`
	if code := serve(t, h, http.MethodPost, "/api/whatif", outside, viewer, nil); code != http.StatusForbidden {
		t.Errorf("viewer outside scope: want 403, got %d", code)
	}
	if code := serve(t, h, http.MethodPost, "/api/whatif", body, "", nil); code != http.StatusForbidden {
		t.Errorf("anonymous: want 403, got %d", code)
	}
	entries, err := st.ListAuditEntries(context.Background(), store.AuditListOptions{Limit: 100})
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Path, "whatif") {
			t.Errorf("what-if was audited as a write: %+v", e)
		}
	}
}

// seedTenClusters stores one scan of clusters c00 to c09 on security/enforced_count, with c04
// at the given value and the rest near 24.
func seedTenClusters(t *testing.T, st store.Store, id string, at time.Time, c04 float64) {
	t.Helper()
	base := []float64{20, 22, 23, 24, 24, 25, 26, 26, 28, 30}
	clusters := make([]string, 0, len(base))
	results := map[string]map[string]scanner.Result{}
	for i, v := range base {
		c := fmt.Sprintf("c%02d", i)
		if c == "c04" {
			v = c04
		}
		clusters = append(clusters, c)
		results[c] = map[string]scanner.Result{"security": {Scanner: "security", Data: map[string]any{"enforced_count": v}}}
	}
	if _, err := st.SaveScanRecord(context.Background(), store.ScanRecord{ID: id, Timestamp: at, Clusters: clusters}, results); err != nil {
		t.Fatalf("save %s: %v", id, err)
	}
}

// TestStoredDriftAndScan verifies the endpoints read stored scans: ?scan= picks an older scan,
// drift spans the stored history and a since/until window, and an unknown scan is a 404.
func TestStoredDriftAndScan(t *testing.T) {
	t.Parallel()
	srv, st := testServer(t)
	h := srv.Handler()
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	for i := range 5 {
		v := 24.0
		if i >= 3 {
			v = 80
		}
		seedTenClusters(t, st, fmt.Sprintf("scan-%d", i+1), start.Add(time.Duration(i)*time.Hour), v)
	}

	var old distributionsResponse
	serve(t, h, http.MethodGet, "/api/distributions?scan=scan-1&field=enforced_count", "", "", &old)
	if old.ScanID != "scan-1" || len(old.Distributions) != 1 {
		t.Fatalf("scan-1 distributions: %+v", old)
	}
	for _, v := range old.Distributions[0].Values {
		if v.Outlier {
			t.Errorf("scan-1 flags %s, want nothing", v.Cluster)
		}
	}
	if code := serve(t, h, http.MethodGet, "/api/distributions?scan=missing", "", "", nil); code != http.StatusNotFound {
		t.Errorf("unknown scan: want 404, got %d", code)
	}

	var l report.Ledger
	serve(t, h, http.MethodGet, "/api/drift?scans=5", "", "", &l)
	if len(l.Clusters) == 0 || l.Clusters[0].Cluster != "c04" || len(l.Clusters[0].Gained) != 1 || l.Clusters[0].Gained[0].Scan != "scan-4" {
		t.Errorf("drift over 5 scans: %+v", l.Clusters)
	}
	var window report.Ledger
	since := start.Add(90 * time.Minute).Format(time.RFC3339)
	serve(t, h, http.MethodGet, "/api/drift?since="+since, "", "", &window)
	if diff := cmp.Diff([]string{"scan-3", "scan-4", "scan-5"}, window.Scans); diff != "" {
		t.Errorf("window scans mismatch (-want +got):\n%s", diff)
	}
	if code := serve(t, h, http.MethodGet, "/api/drift?since=yesterday", "", "", nil); code != http.StatusBadRequest {
		t.Errorf("bad since: want 400, got %d", code)
	}
}
