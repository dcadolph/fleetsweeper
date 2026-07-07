package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// closedStore returns a SQLite store whose underlying database has been closed.
// Every subsequent query fails, which exercises the error-return branch of each
// method without needing to inject faults into a live connection.
func closedStore(t *testing.T) *SQLite {
	t.Helper()
	s, err := NewSQLite(filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	return s
}

// TestClosedStoreErrors verifies every Store method surfaces an error rather
// than panicking when the database is unavailable. Each row exercises the
// query-failure branch of one method.
func TestClosedStoreErrors(t *testing.T) { //nolint:funlen // Exhaustive method table.
	t.Parallel()
	s := closedStore(t)
	ctx := context.Background()

	results := map[string]map[string]scanner.Result{
		"c": {"version": {Scanner: "version", Data: map[string]any{"k": "v"}}},
	}
	validKey := APIKeyRecord{ID: "k", TokenHash: "h", Name: "n", Role: RoleViewer, ClusterScope: []string{ScopeWildcard}}

	tests := []struct {
		Name string
		Fn   func(context.Context, *SQLite) error
	}{{
		Name: "SaveScan", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.SaveScan(ctx, []string{"c"}, results)
			return err
		},
	}, {
		Name: "GetScan", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.GetScan(ctx, "id")
			return err
		},
	}, {
		Name: "ListScans", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.ListScans(ctx, 10)
			return err
		},
	}, {
		Name: "GetScanResults", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.GetScanResults(ctx, "id")
			return err
		},
	}, {
		Name: "ListClusters", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.ListClusters(ctx)
			return err
		},
	}, {
		Name: "SaveGroup", Fn: func(ctx context.Context, s *SQLite) error {
			return s.SaveGroup(ctx, "g", []string{"c"})
		},
	}, {
		Name: "GetGroup", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.GetGroup(ctx, "g")
			return err
		},
	}, {
		Name: "ListGroups", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.ListGroups(ctx)
			return err
		},
	}, {
		Name: "DeleteGroup", Fn: func(ctx context.Context, s *SQLite) error {
			return s.DeleteGroup(ctx, "g")
		},
	}, {
		Name: "AddClusterToGroup", Fn: func(ctx context.Context, s *SQLite) error {
			return s.AddClusterToGroup(ctx, "g", "c")
		},
	}, {
		Name: "RemoveClusterFromGroup", Fn: func(ctx context.Context, s *SQLite) error {
			return s.RemoveClusterFromGroup(ctx, "g", "c")
		},
	}, {
		Name: "GetClusterHistory", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.GetClusterHistory(ctx, "c", 10)
			return err
		},
	}, {
		Name: "GetScansByTimeRange", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.GetScansByTimeRange(ctx, time.Now().Add(-time.Hour), time.Now())
			return err
		},
	}, {
		Name: "Prune", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.Prune(ctx, time.Now())
			return err
		},
	}, {
		Name: "Vacuum", Fn: func(ctx context.Context, s *SQLite) error {
			return s.Vacuum(ctx)
		},
	}, {
		Name: "VacuumInto", Fn: func(ctx context.Context, s *SQLite) error {
			return s.VacuumInto(ctx, filepath.Join(t.TempDir(), "snap.db"))
		},
	}, {
		Name: "SetLocation", Fn: func(ctx context.Context, s *SQLite) error {
			return s.SetLocation(ctx, LocationRecord{Cluster: "c", Lat: 1, Lng: 2})
		},
	}, {
		Name: "GetLocation", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.GetLocation(ctx, "c")
			return err
		},
	}, {
		Name: "ListLocations", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.ListLocations(ctx)
			return err
		},
	}, {
		Name: "DeleteLocation", Fn: func(ctx context.Context, s *SQLite) error {
			return s.DeleteLocation(ctx, "c")
		},
	}, {
		Name: "SaveAck", Fn: func(ctx context.Context, s *SQLite) error {
			return s.SaveAck(ctx, AckRecord{Fingerprint: "fp"})
		},
	}, {
		Name: "DeleteAck", Fn: func(ctx context.Context, s *SQLite) error {
			return s.DeleteAck(ctx, "fp")
		},
	}, {
		Name: "ListAcks", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.ListAcks(ctx)
			return err
		},
	}, {
		Name: "IsAcked", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.IsAcked(ctx, "fp")
			return err
		},
	}, {
		Name: "SaveAPIKey", Fn: func(ctx context.Context, s *SQLite) error {
			return s.SaveAPIKey(ctx, validKey)
		},
	}, {
		Name: "GetAPIKeyByHash", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.GetAPIKeyByHash(ctx, "h")
			return err
		},
	}, {
		Name: "GetAPIKey", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.GetAPIKey(ctx, "k")
			return err
		},
	}, {
		Name: "ListAPIKeys", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.ListAPIKeys(ctx)
			return err
		},
	}, {
		Name: "RevokeAPIKey", Fn: func(ctx context.Context, s *SQLite) error {
			return s.RevokeAPIKey(ctx, "k")
		},
	}, {
		Name: "TouchAPIKey", Fn: func(ctx context.Context, s *SQLite) error {
			return s.TouchAPIKey(ctx, "k", time.Now())
		},
	}, {
		Name: "SaveAuditEntry", Fn: func(ctx context.Context, s *SQLite) error {
			return s.SaveAuditEntry(ctx, AuditEntry{Method: "GET", Path: "/", Status: 200})
		},
	}, {
		Name: "ListAuditEntries", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.ListAuditEntries(ctx, AuditListOptions{})
			return err
		},
	}, {
		Name: "PruneAuditEntries", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.PruneAuditEntries(ctx, time.Now())
			return err
		},
	}, {
		Name: "UpsertAlert", Fn: func(ctx context.Context, s *SQLite) error {
			return s.UpsertAlert(ctx, AlertRecord{Fingerprint: "fp", Cluster: "c", Status: "firing", AlertName: "a"})
		},
	}, {
		Name: "GetAlert", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.GetAlert(ctx, "fp")
			return err
		},
	}, {
		Name: "ListAlerts", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.ListAlerts(ctx, AlertListOptions{})
			return err
		},
	}, {
		Name: "PruneAlerts", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.PruneAlerts(ctx, time.Now())
			return err
		},
	}, {
		Name: "SetClusterTag", Fn: func(ctx context.Context, s *SQLite) error {
			return s.SetClusterTag(ctx, "c", "env", "prod")
		},
	}, {
		Name: "DeleteClusterTag", Fn: func(ctx context.Context, s *SQLite) error {
			return s.DeleteClusterTag(ctx, "c", "env")
		},
	}, {
		Name: "GetClusterTags", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.GetClusterTags(ctx, "c")
			return err
		},
	}, {
		Name: "ListClusterTags", Fn: func(ctx context.Context, s *SQLite) error {
			_, err := s.ListClusterTags(ctx)
			return err
		},
	}, {
		Name: "Ping", Fn: func(ctx context.Context, s *SQLite) error {
			return s.Ping(ctx)
		},
	}}

	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			if err := test.Fn(ctx, s); err == nil {
				t.Errorf("test %d (%s): expected an error on a closed store, got nil", i, test.Name)
			}
		})
	}
}
