package store

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// execRaw runs a statement directly against the underlying database so tests can
// plant malformed rows that only the decode paths can observe.
func execRaw(t *testing.T, s *SQLite, query string, args ...any) {
	t.Helper()
	if _, err := s.db.ExecContext(context.Background(), query, args...); err != nil {
		t.Fatalf("raw exec: %v", err)
	}
}

const validTS = "2026-01-01T00:00:00Z"

// TestScanRecordDecodeErrors verifies GetScan and ListScans surface a query
// error when a stored row cannot be decoded.
func TestScanRecordDecodeErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		Name      string
		Timestamp string
		Clusters  string
		Scanners  string
	}{{ // Test 0: An unparseable timestamp fails decoding.
		Name: "bad timestamp", Timestamp: "not-a-time", Clusters: `["c"]`, Scanners: `["s"]`,
	}, { // Test 1: Malformed clusters JSON fails decoding.
		Name: "bad clusters", Timestamp: validTS, Clusters: `not-json`, Scanners: `["s"]`,
	}, { // Test 2: Malformed scanners JSON fails decoding.
		Name: "bad scanners", Timestamp: validTS, Clusters: `["c"]`, Scanners: `not-json`,
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			s := newTestSQLite(t)
			execRaw(t, s, "INSERT INTO scans (id, timestamp, clusters, scanners) VALUES (?, ?, ?, ?)",
				"row", test.Timestamp, test.Clusters, test.Scanners)

			if _, err := s.GetScan(ctx, "row"); !errors.Is(err, ErrQuery) {
				t.Errorf("test %d: GetScan want ErrQuery, got %v", i, err)
			}
			if _, err := s.ListScans(ctx, 10); !errors.Is(err, ErrQuery) {
				t.Errorf("test %d: ListScans want ErrQuery, got %v", i, err)
			}
		})
	}
}

// TestGetScanResultsDecodeError verifies malformed result JSON surfaces an error.
func TestGetScanResultsDecodeError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newTestSQLite(t)

	execRaw(t, s, "INSERT INTO scans (id, timestamp, clusters, scanners) VALUES (?, ?, ?, ?)",
		"sr", validTS, `["c"]`, `["version"]`)
	execRaw(t, s, "INSERT INTO scan_results (scan_id, cluster, scanner, data_json) VALUES (?, ?, ?, ?)",
		"sr", "c", "version", "not-json")

	if _, err := s.GetScanResults(ctx, "sr"); !errors.Is(err, ErrQuery) {
		t.Errorf("want ErrQuery, got %v", err)
	}
}

// TestGetAlertDecodeError verifies malformed label JSON on an alert row surfaces
// an error.
func TestGetAlertDecodeError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newTestSQLite(t)

	execRaw(t, s, `INSERT INTO alerts
		(fingerprint, cluster, status, alertname, received_at, labels_json, annotations_json)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"fp", "c", "firing", "A", validTS, "not-json", "{}")

	if _, err := s.GetAlert(ctx, "fp"); !errors.Is(err, ErrQuery) {
		t.Errorf("want ErrQuery, got %v", err)
	}
}

// TestGetAPIKeyDecodeErrors verifies malformed scope JSON and an unparseable
// created_at both surface as query errors.
func TestGetAPIKeyDecodeErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		Name      string
		Scope     string
		CreatedAt string
	}{{ // Test 0: Malformed cluster_scope JSON fails decoding.
		Name: "bad scope", Scope: "not-json", CreatedAt: validTS,
	}, { // Test 1: Unparseable created_at fails decoding.
		Name: "bad created_at", Scope: `["*"]`, CreatedAt: "not-a-time",
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			s := newTestSQLite(t)
			execRaw(t, s, `INSERT INTO api_keys
				(id, token_hash, name, role, cluster_scope, created_at)
				VALUES (?, ?, ?, ?, ?, ?)`,
				"k", "h", "n", RoleViewer, test.Scope, test.CreatedAt)

			if _, err := s.GetAPIKey(ctx, "k"); !errors.Is(err, ErrQuery) {
				t.Errorf("test %d: GetAPIKey want ErrQuery, got %v", i, err)
			}
			if _, err := s.ListAPIKeys(ctx); !errors.Is(err, ErrQuery) {
				t.Errorf("test %d: ListAPIKeys want ErrQuery, got %v", i, err)
			}
		})
	}
}

// TestListClustersWithGroups verifies group membership is joined onto each
// cluster record.
func TestListClustersWithGroups(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newTestSQLite(t)

	results := map[string]map[string]scanner.Result{
		"x": {"version": {Scanner: "version", Data: map[string]any{}}},
	}
	if _, err := s.SaveScan(ctx, []string{"x"}, results); err != nil {
		t.Fatalf("save scan: %v", err)
	}
	if err := s.SaveGroup(ctx, "prod", []string{"x"}); err != nil {
		t.Fatalf("save group: %v", err)
	}

	clusters, err := s.ListClusters(ctx)
	if err != nil {
		t.Fatalf("list clusters: %v", err)
	}
	if len(clusters) != 1 {
		t.Fatalf("want 1 cluster, got %d", len(clusters))
	}
	if diff := cmp.Diff([]string{"prod"}, clusters[0].Groups, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("groups (-want +got):\n%s", diff)
	}
}
