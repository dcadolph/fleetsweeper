package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"

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
		"prod-a": {"version": {Scanner: "version", Data: map[string]any{"gitVersion": "v1.29.0"}}},
		"prod-b": {"version": {Scanner: "version", Data: map[string]any{"gitVersion": "v1.28.3"}}},
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
		const fp = "fp-contract-1"
		ack, err := c.AckFinding(ctx, fp, client.AckRequest{AckBy: "tester", Reason: "known noise"})
		if err != nil {
			t.Fatalf("ack finding: %v", err)
		}
		if ack.Fingerprint != fp {
			t.Errorf("ack fingerprint = %q, want %q", ack.Fingerprint, fp)
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
