package client_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/client"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/server"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// newContractServer starts a real server backed by a temporary SQLite store
// and returns a client pointed at it plus the store for seeding.
func newContractServer(t *testing.T, insecure bool, token string) (*client.Client, store.Store, string) {
	t.Helper()
	st, err := store.Open("sqlite", filepath.Join(t.TempDir(), "fleet.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	srv := server.New(server.Config{
		Store:     st,
		Registry:  scanner.NewRegistry(),
		Log:       zap.NewNop(),
		Insecure:  insecure,
		AuthToken: token,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	var opts []client.Option
	if token != "" {
		opts = append(opts, client.WithToken(token))
	}
	return client.New(ts.URL, opts...), st, ts.URL
}

// seedScan persists one two-cluster scan and returns its id.
func seedScan(t *testing.T, st store.Store) string {
	t.Helper()
	results := map[string]map[string]scanner.Result{
		"prod-a": {"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.29.0"}}},
		"prod-b": {"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.28.3"}}},
	}
	id, err := st.SaveScan(context.Background(), []string{"prod-a", "prod-b"}, results)
	if err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	return id
}

// okOrAPIError accepts either a nil error or a well-formed *APIError. It is used
// for endpoints whose data depends on the host environment (for example the
// kubeconfig), where the client plumbing is what matters, not the payload.
func okOrAPIError(t *testing.T, label string, err error) {
	t.Helper()
	if err == nil {
		return
	}
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) {
		t.Errorf("%s: want nil or *APIError, got %v", label, err)
	}
}

// TestContract drives the SDK against a live in-process server to confirm the
// client and server agree on paths, query parameters, request bodies, and
// response shapes. Subtests run serially because they share one seeded server.
func TestContract(t *testing.T) {
	t.Parallel()
	c, st, _ := newContractServer(t, true, "")
	scanID := seedScan(t, st)
	ctx := context.Background()

	t.Run("health", func(t *testing.T) {
		if err := c.Healthz(ctx); err != nil {
			t.Errorf("healthz: %v", err)
		}
		if err := c.Readyz(ctx); err != nil {
			t.Errorf("readyz: %v", err)
		}
	})

	t.Run("scans", func(t *testing.T) {
		scans, err := c.ListScans(ctx, 10)
		if err != nil {
			t.Fatalf("list scans: %v", err)
		}
		if !slices.ContainsFunc(scans, func(s client.ScanRecord) bool { return s.ID == scanID }) {
			t.Errorf("list scans missing seeded id %s", scanID)
		}
		rec, err := c.GetScan(ctx, scanID)
		if err != nil {
			t.Fatalf("get scan: %v", err)
		}
		if diff := cmp.Diff([]string{"prod-a", "prod-b"}, rec.Clusters, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("scan clusters mismatch (-want +got):\n%s", diff)
		}
		report, err := c.GetScanReport(ctx, scanID)
		if err != nil {
			t.Fatalf("get scan report: %v", err)
		}
		if report.Summary.ClusterCount != 2 {
			t.Errorf("report cluster count = %d, want 2", report.Summary.ClusterCount)
		}
		if report.FleetScore.Score < 0 || report.FleetScore.Score > 100 {
			t.Errorf("fleet score out of range: %d", report.FleetScore.Score)
		}
	})

	t.Run("clusters", func(t *testing.T) {
		clusters, err := c.ListClusters(ctx)
		if err != nil {
			t.Fatalf("list clusters: %v", err)
		}
		names := make([]string, len(clusters))
		for i, cl := range clusters {
			names[i] = cl.Name
		}
		for _, want := range []string{"prod-a", "prod-b"} {
			if !slices.Contains(names, want) {
				t.Errorf("list clusters missing %s, got %v", want, names)
			}
		}
		detail, err := c.GetClusterDetail(ctx, "prod-a")
		if err != nil {
			t.Fatalf("cluster detail: %v", err)
		}
		if detail.Cluster != "prod-a" {
			t.Errorf("cluster detail name = %q, want prod-a", detail.Cluster)
		}
	})

	t.Run("groups", func(t *testing.T) {
		if err := c.CreateGroup(ctx, client.CreateGroupRequest{Name: "prod", Clusters: []string{"prod-a", "prod-b"}}); err != nil {
			t.Fatalf("create group: %v", err)
		}
		hasProd := func(gs []client.Group) bool {
			return slices.ContainsFunc(gs, func(g client.Group) bool { return g.Name == "prod" })
		}
		groups, err := c.ListGroups(ctx)
		if err != nil {
			t.Fatalf("list groups: %v", err)
		}
		if !hasProd(groups) {
			t.Errorf("list groups missing prod, got %v", groups)
		}
		if err := c.DeleteGroup(ctx, "prod"); err != nil {
			t.Fatalf("delete group: %v", err)
		}
		groups, err = c.ListGroups(ctx)
		if err != nil {
			t.Fatalf("list groups after delete: %v", err)
		}
		if hasProd(groups) {
			t.Errorf("group prod still present after delete")
		}
	})

	t.Run("insights", func(t *testing.T) {
		if _, err := c.Outliers(ctx, 0); err != nil {
			t.Errorf("outliers: %v", err)
		}
		if _, err := c.Capacity(ctx); err != nil {
			t.Errorf("capacity: %v", err)
		}
		if _, err := c.FleetForecast(ctx, 0); err != nil {
			t.Errorf("fleet forecast: %v", err)
		}
		if _, err := c.ClustersForecast(ctx); err != nil {
			t.Errorf("clusters forecast: %v", err)
		}
		cost, err := c.Cost(ctx)
		if err != nil {
			t.Fatalf("cost: %v", err)
		}
		if cost.Currency != "USD" {
			t.Errorf("cost currency = %q, want USD", cost.Currency)
		}
		if _, err := c.Integrations(ctx); err != nil {
			t.Errorf("integrations: %v", err)
		}
		if _, err := c.Trends(ctx, 0); err != nil {
			t.Errorf("trends: %v", err)
		}
	})

	t.Run("findings ack", func(t *testing.T) {
		report, err := c.GetScanReport(ctx, scanID)
		if err != nil {
			t.Fatalf("get scan report: %v", err)
		}
		if len(report.Findings) == 0 {
			t.Fatal("seeded report has no findings to ack")
		}
		f := report.Findings[0]
		fp := f.Fingerprint
		ack, err := c.AckFinding(ctx, fp, client.AckRequest{AckBy: "tester", Reason: "known noise"})
		if err != nil {
			t.Fatalf("ack finding: %v", err)
		}
		want := client.AckRecord{
			Fingerprint: fp, Cluster: f.Cluster, Scanner: f.Scanner, Title: f.Title,
			AckBy: "tester", Reason: "known noise",
		}
		ignore := cmpopts.IgnoreFields(client.AckRecord{}, "CreatedAt")
		if diff := cmp.Diff(want, *ack, ignore); diff != "" {
			t.Errorf("ack mismatch (-want +got):\n%s", diff)
		}
		acks, err := c.ListAcks(ctx)
		if err != nil {
			t.Fatalf("list acks: %v", err)
		}
		if !slices.ContainsFunc(acks, func(a client.AckRecord) bool { return a.Fingerprint == fp }) {
			t.Errorf("list acks missing %s", fp)
		}
		if err := c.DeleteFindingAck(ctx, fp); err != nil {
			t.Errorf("delete finding ack: %v", err)
		}
	})

	t.Run("alerts and timeline", func(t *testing.T) {
		alerts, err := c.ListAlerts(ctx, client.AlertQuery{Limit: 50})
		if err != nil {
			t.Fatalf("list alerts: %v", err)
		}
		if alerts.Count != len(alerts.Alerts) {
			t.Errorf("alerts count = %d, len = %d", alerts.Count, len(alerts.Alerts))
		}
		timeline, err := c.ClusterTimeline(ctx, "prod-a", 50)
		if err != nil {
			t.Fatalf("cluster timeline: %v", err)
		}
		if timeline.Cluster != "prod-a" {
			t.Errorf("timeline cluster = %q, want prod-a", timeline.Cluster)
		}
	})

	t.Run("locations", func(t *testing.T) {
		if err := c.SetLocation(ctx, "prod-a", client.LocationRequest{Lat: 40.7, Lng: -74.0, Site: "nyc"}); err != nil {
			t.Fatalf("set location: %v", err)
		}
		if _, err := c.ListLocations(ctx); err != nil {
			t.Errorf("list locations: %v", err)
		}
		if err := c.DeleteLocation(ctx, "prod-a"); err != nil {
			t.Errorf("delete location: %v", err)
		}
	})

	t.Run("environment dependent", func(t *testing.T) {
		if _, err := c.Geo(ctx); err != nil {
			t.Errorf("geo: %v", err)
		}
		okOrAPIError(t, "contexts", func() error { _, err := c.Contexts(ctx); return err }())
	})

	t.Run("trigger scan empty", func(t *testing.T) {
		_, err := c.TriggerScan(ctx, client.TriggerScanRequest{})
		var apiErr *client.APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("trigger scan: want *APIError, got %v", err)
		}
		if apiErr.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", apiErr.StatusCode, http.StatusBadRequest)
		}
		if apiErr.Message != "no contexts specified" {
			t.Errorf("message = %q, want %q", apiErr.Message, "no contexts specified")
		}
	})

	t.Run("ack finding unknown", func(t *testing.T) {
		_, err := c.AckFinding(ctx, "fp-unknown", client.AckRequest{AckBy: "tester"})
		var apiErr *client.APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("ack finding: want *APIError, got %v", err)
		}
		if apiErr.StatusCode != http.StatusNotFound {
			t.Errorf("status = %d, want %d", apiErr.StatusCode, http.StatusNotFound)
		}
	})

	t.Run("ack alert unknown", func(t *testing.T) {
		_, err := c.AckAlert(ctx, "fp-unknown", client.AckAlertRequest{AckBy: "tester"})
		var apiErr *client.APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("ack alert: want *APIError, got %v", err)
		}
		if apiErr.StatusCode != http.StatusNotFound {
			t.Errorf("status = %d, want %d", apiErr.StatusCode, http.StatusNotFound)
		}
	})

	t.Run("cluster trends", func(t *testing.T) {
		raw, err := c.ClusterTrends(ctx, "prod-a")
		if err != nil {
			t.Fatalf("cluster trends: %v", err)
		}
		if !strings.Contains(string(raw), `"cluster":"prod-a"`) {
			t.Errorf("cluster trends = %s, want it to contain %q", raw, `"cluster":"prod-a"`)
		}
	})
}

// TestContractAuth confirms the client sends its bearer token and that the
// server enforces it on mutating endpoints.
func TestContractAuth(t *testing.T) {
	t.Parallel()
	const token = "s3cret-token"
	ctx := context.Background()
	_, _, base := newContractServer(t, false, token)

	authed := client.New(base, client.WithToken(token))
	if err := authed.CreateGroup(ctx, client.CreateGroupRequest{Name: "g1"}); err != nil {
		t.Errorf("authed create group: %v", err)
	}

	anon := client.New(base)
	err := anon.CreateGroup(ctx, client.CreateGroupRequest{Name: "g2"})
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("anon create group: want *APIError, got %v", err)
	}
	if apiErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("anon create group status = %d, want 401", apiErr.StatusCode)
	}
}

// TestContractScanners verifies the scanner catalog comes back complete.
func TestContractScanners(t *testing.T) {
	t.Parallel()
	c, _, _ := newContractServer(t, true, "")
	got, err := c.Scanners(context.Background())
	if err != nil {
		t.Fatalf("scanners: %v", err)
	}
	if len(got) != 24 {
		t.Errorf("scanners: want 24, got %d", len(got))
	}
	for _, s := range got {
		if s.ID == "" || s.Label == "" || s.Description == "" || s.Category == "" {
			t.Errorf("incomplete scanner entry %+v", s)
		}
	}
}

// TestContractWithScan verifies every scan-aware read reports on the scan
// WithScan names rather than the latest, and that an unknown scan is a 404.
func TestContractWithScan(t *testing.T) {
	t.Parallel()
	c, st, _ := newContractServer(t, true, "")
	ctx := context.Background()
	at := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	save := func(id string, offset time.Duration, clusters ...string) {
		results := map[string]map[string]scanner.Result{}
		for _, cl := range clusters {
			results[cl] = map[string]scanner.Result{"version": {Scanner: "version", Data: map[string]any{"gitVersion": "v1.29.0"}}}
		}
		rec := store.ScanRecord{ID: id, Timestamp: at.Add(offset), Clusters: clusters}
		if _, err := st.SaveScanRecord(ctx, rec, results); err != nil {
			t.Fatalf("save %s: %v", id, err)
		}
	}
	save("scan-old", 0, "prod-a", "prod-b", "prod-c")
	save("scan-new", time.Hour, "dev-x", "dev-y", "dev-z")

	outliers, err := c.Outliers(ctx, 0, client.WithScan("scan-old"))
	if err != nil || outliers.ScanID != "scan-old" {
		t.Errorf("outliers: want scan-old, got %+v, %v", outliers, err)
	}
	if latest, err := c.Outliers(ctx, 0); err != nil || latest.ScanID != "scan-new" {
		t.Errorf("outliers without a scan: want scan-new, got %+v, %v", latest, err)
	}
	capacity, err := c.Capacity(ctx, client.WithScan("scan-old"))
	if err != nil || capacity.ScanID != "scan-old" {
		t.Errorf("capacity: want scan-old, got %+v, %v", capacity, err)
	}
	cohorts, err := c.Cohorts(ctx, 0, client.WithScan("scan-old"))
	if err != nil || cohorts.ScanID != "scan-old" {
		t.Errorf("cohorts: want scan-old, got %+v, %v", cohorts, err)
	}
	if _, err := c.GetClusterDetail(ctx, "prod-a", client.WithScan("scan-old")); err != nil {
		t.Errorf("detail of an old-scan cluster: %v", err)
	}
	geo, err := c.Geo(ctx, client.WithScan("scan-old"))
	if err != nil || !strings.Contains(string(geo), "prod-a") || strings.Contains(string(geo), "dev-x") {
		t.Errorf("geo: want the old scan's clusters, got %s, %v", geo, err)
	}
	if _, err := c.Cost(ctx, client.WithScan("scan-old")); err != nil {
		t.Errorf("cost: %v", err)
	}

	for label, call := range map[string]func() error{
		"outliers": func() error { _, err := c.Outliers(ctx, 0, client.WithScan("missing")); return err },
		"capacity": func() error { _, err := c.Capacity(ctx, client.WithScan("missing")); return err },
		"cohorts":  func() error { _, err := c.Cohorts(ctx, 0, client.WithScan("missing")); return err },
		"geo":      func() error { _, err := c.Geo(ctx, client.WithScan("missing")); return err },
		"detail":   func() error { _, err := c.GetClusterDetail(ctx, "prod-a", client.WithScan("missing")); return err },
		"cost":     func() error { _, err := c.Cost(ctx, client.WithScan("missing")); return err },
	} {
		var apiErr *client.APIError
		if err := call(); !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
			t.Errorf("%s with an unknown scan: want a 404 APIError, got %v", label, err)
		}
	}
}

// TestContractNorm drives the distribution, history, attribution, drift,
// cohort map, and what-if methods against stored scans where c04 steps far
// from the fleet at the fourth scan.
func TestContractNorm(t *testing.T) {
	t.Parallel()
	c, st, _ := newContractServer(t, true, "")
	ctx := context.Background()
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	base := []float64{20, 22, 23, 24, 24, 25, 26, 26, 28, 30}
	for n := 1; n <= 5; n++ {
		clusters := make([]string, 0, len(base))
		results := map[string]map[string]scanner.Result{}
		for i, v := range base {
			cl := fmt.Sprintf("c%02d", i)
			if cl == "c04" && n >= 4 {
				v = 80
			}
			clusters = append(clusters, cl)
			results[cl] = map[string]scanner.Result{"security": {Scanner: "security", Data: map[string]any{"unenforced_count": v}}}
		}
		rec := store.ScanRecord{ID: fmt.Sprintf("scan-%d", n), Timestamp: start.Add(time.Duration(n) * time.Hour), Clusters: clusters}
		if _, err := st.SaveScanRecord(ctx, rec, results); err != nil {
			t.Fatalf("save: %v", err)
		}
	}

	dists, err := c.Distributions(ctx, client.DistributionQuery{Field: "unenforced_count"})
	if err != nil || dists.ScanID != "scan-5" || len(dists.Distributions) != 1 {
		t.Fatalf("distributions: %+v, %v", dists, err)
	}
	flagged := 0
	for _, v := range dists.Distributions[0].Values {
		if v.Outlier {
			flagged++
		}
	}
	if flagged != 1 {
		t.Errorf("want one flagged cluster, got %d", flagged)
	}

	hist, err := c.DistributionHistory(ctx, "security", "unenforced_count", "", 5)
	if err != nil || len(hist.Points) != 5 || hist.Points[0].ScanID != "scan-1" {
		t.Errorf("history: %+v, %v", hist, err)
	}

	attr, err := c.ScoreAttribution(ctx, client.WithScan("scan-1"))
	if err != nil || attr.ScanID != "scan-1" || attr.Attribution == nil {
		t.Errorf("attribution: %+v, %v", attr, err)
	}

	drift, err := c.Drift(ctx, client.DriftQuery{Scans: 5})
	if err != nil || len(drift.Clusters) == 0 || drift.Clusters[0].Cluster != "c04" {
		t.Fatalf("drift: %+v, %v", drift, err)
	}
	if g := drift.Clusters[0].Gained; len(g) != 1 || g[0].Scan != "scan-4" {
		t.Errorf("drift gained: %+v", g)
	}
	window, err := c.Drift(ctx, client.DriftQuery{Since: start.Add(150 * time.Minute)})
	if err != nil || len(window.Scans) != 3 {
		t.Errorf("drift window: %+v, %v", window, err)
	}

	m, err := c.CohortMap(ctx)
	if err != nil || len(m.Map.Points) != 10 {
		t.Errorf("cohort map: %+v, %v", m, err)
	}

	out, err := c.WhatIf(ctx, client.WhatIfRequest{Cluster: "c04", Scanner: "security", Field: "unenforced_count"})
	if err != nil {
		t.Fatalf("whatif: %v", err)
	}
	if out.Outcome.Fix.Kind != "median" || out.Outcome.ScoreAfter <= out.Outcome.ScoreBefore {
		t.Errorf("whatif outcome: %+v", out.Outcome)
	}
	var apiErr *client.APIError
	if _, err := c.WhatIf(ctx, client.WhatIfRequest{Cluster: "c04", Scanner: "security", Field: "nope"}); !errors.As(err, &apiErr) ||
		apiErr.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("whatif on an unknown field: want 422, got %v", err)
	}
}

// TestContractDemoStrict decodes every typed read endpoint of the demo fleet with unknown
// fields disallowed, so a field the server sends and the client drops fails the test.
func TestContractDemoStrict(t *testing.T) {
	t.Parallel()
	st, err := store.Open("sqlite", filepath.Join(t.TempDir(), "fleet.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	if err := server.SeedDemo(ctx, st, time.Now()); err != nil {
		t.Fatalf("seed demo: %v", err)
	}
	srv := server.New(server.Config{
		Store: st, Registry: scanner.NewRegistry(), Log: zap.NewNop(), Demo: true,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	c := client.New(ts.URL)

	scans, err := c.ListScans(ctx, 1)
	if err != nil || len(scans) == 0 {
		t.Fatalf("list scans: %v, %d", err, len(scans))
	}
	clusters, err := c.ListClusters(ctx)
	if err != nil || len(clusters) == 0 {
		t.Fatalf("list clusters: %v, %d", err, len(clusters))
	}
	dists, err := c.Distributions(ctx, client.DistributionQuery{})
	if err != nil || len(dists.Distributions) == 0 {
		t.Fatalf("distributions: %v", err)
	}
	d := dists.Distributions[0]
	histPath := "/api/distributions/history?scanner=" + d.Scanner + "&field=" + d.Field

	// reportWire is Report plus the top-level keys the client deliberately omits.
	type reportWire struct {
		client.Report
		Sections   json.RawMessage `json:"sections"`
		Categories json.RawMessage `json:"categories"`
		Brief      json.RawMessage `json:"brief"`
		Incidents  json.RawMessage `json:"incidents"`
		Degraded   json.RawMessage `json:"degraded"`
	}

	tests := []struct {
		Dest func() any
		Name string
		Path string
	}{
		{ // Test 0: Report.
			Dest: func() any { return &reportWire{} },
			Name: "report", Path: "/api/scans/" + scans[0].ID + "/report",
		},
		{ // Test 1: Outliers.
			Dest: func() any { return &client.OutliersResponse{} },
			Name: "outliers", Path: "/api/outliers",
		},
		{ // Test 2: Distributions.
			Dest: func() any { return &client.DistributionsResponse{} },
			Name: "distributions", Path: "/api/distributions",
		},
		{ // Test 3: Cohorts.
			Dest: func() any { return &client.CohortsResponse{} },
			Name: "cohorts", Path: "/api/cohorts",
		},
		{ // Test 4: Capacity.
			Dest: func() any { return &client.CapacityResponse{} },
			Name: "capacity", Path: "/api/capacity",
		},
		{ // Test 5: Cluster detail.
			Dest: func() any { return &client.ClusterDetail{} },
			Name: "detail", Path: "/api/clusters/" + clusters[0].Name + "/detail",
		},
		{ // Test 6: Attribution.
			Dest: func() any { return &client.AttributionResponse{} },
			Name: "attribution", Path: "/api/score/attribution",
		},
		{ // Test 7: Distribution history.
			Dest: func() any { return &client.HistoryResponse{} },
			Name: "history", Path: histPath,
		},
		{ // Test 8: Drift.
			Dest: func() any { return &client.DriftLedger{} },
			Name: "drift", Path: "/api/drift",
		},
		{ // Test 9: Cohort map.
			Dest: func() any { return &client.CohortMapResponse{} },
			Name: "cohort map", Path: "/api/cohorts/map",
		},
		{ // Test 10: Fleet forecast.
			Dest: func() any { return &client.FleetForecastResponse{} },
			Name: "fleet forecast", Path: "/api/forecast/fleet-score",
		},
		{ // Test 11: Cluster forecasts.
			Dest: func() any { return &client.ClustersForecastResponse{} },
			Name: "cluster forecasts", Path: "/api/forecast/clusters",
		},
		{ // Test 12: Alerts.
			Dest: func() any { return &client.AlertsResponse{} },
			Name: "alerts", Path: "/api/alerts",
		},
		{ // Test 13: Timeline.
			Dest: func() any { return &client.TimelineResponse{} },
			Name: "timeline", Path: "/api/clusters/" + clusters[0].Name + "/timeline",
		},
		{ // Test 14: Cost.
			Dest: func() any { return &client.CostAnalysis{} },
			Name: "cost", Path: "/api/cost",
		},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			resp, err := http.Get(ts.URL + test.Path)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d: %s", resp.StatusCode, body)
			}
			dec := json.NewDecoder(bytes.NewReader(body))
			dec.DisallowUnknownFields()
			if err := dec.Decode(test.Dest()); err != nil {
				t.Errorf("strict decode: %v", err)
			}
		})
	}
}

// countingTransport counts round trips and delegates to the default transport.
type countingTransport struct {
	// Count is the number of requests sent through the transport.
	Count int
}

// RoundTrip counts the request and forwards it.
func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.Count++
	return http.DefaultTransport.RoundTrip(r)
}

// TestClientOptions confirms WithUserAgent and WithHTTPClient reach the wire.
func TestClientOptions(t *testing.T) {
	t.Parallel()
	var gotUA string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	ctx := context.Background()

	t.Run("user agent", func(t *testing.T) {
		c := client.New(ts.URL, client.WithUserAgent("custom-agent/9"))
		if err := c.Healthz(ctx); err != nil {
			t.Fatalf("healthz: %v", err)
		}
		if gotUA != "custom-agent/9" {
			t.Errorf("User-Agent = %q, want %q", gotUA, "custom-agent/9")
		}
	})

	t.Run("http client", func(t *testing.T) {
		rt := &countingTransport{}
		c := client.New(ts.URL, client.WithHTTPClient(&http.Client{Transport: rt}))
		if err := c.Healthz(ctx); err != nil {
			t.Fatalf("healthz: %v", err)
		}
		if rt.Count != 1 {
			t.Errorf("round trips = %d, want 1", rt.Count)
		}
	})
}

// TestAPIErrorError checks the exact error strings.
func TestAPIErrorError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WantString string
		Err        client.APIError
	}{{ // Test 0: Message present.
		Err:        client.APIError{StatusCode: 404, Message: "not found"},
		WantString: "fleetsweeper: http 404: not found",
	}, { // Test 1: Empty message.
		Err:        client.APIError{StatusCode: 502},
		WantString: "fleetsweeper: http 502",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(test.WantString, test.Err.Error(), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
