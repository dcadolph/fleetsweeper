package store

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// TestSQLiteMemoryConcurrent guards against the in-memory connection-pool bug:
// with more than one pooled connection a ":memory:" database gives each
// connection its own empty schema, so concurrent queries intermittently fail
// with "no such table". Pinning the pool to a single connection must keep the
// migrated schema visible to every concurrent caller.
func TestSQLiteMemoryConcurrent(t *testing.T) {
	t.Parallel()

	s, err := NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.ListScans(context.Background(), 10); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if strings.Contains(err.Error(), "no such table") {
			t.Fatalf("in-memory schema not visible to a pooled connection: %v", err)
		}
		t.Errorf("concurrent ListScans on in-memory store failed: %v", err)
	}
}

// TestSQLiteMemoryListsMemberships verifies listing groups and clusters on the one-connection
// in-memory store finishes: a query nested inside an open row set would wait forever for a
// second connection.
func TestSQLiteMemoryListsMemberships(t *testing.T) {
	t.Parallel()
	s, err := NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.SaveScanRecord(ctx, ScanRecord{ID: "s1", Timestamp: time.Now(), Clusters: []string{"a", "b", "c"}}, nil); err != nil {
		t.Fatalf("save scan: %v", err)
	}
	for _, g := range []GroupRecord{{Name: "one", Clusters: []string{"b", "a"}}, {Name: "two", Clusters: []string{"a", "c"}}} {
		if err := s.SaveGroup(ctx, g.Name, g.Clusters); err != nil {
			t.Fatalf("save group: %v", err)
		}
	}
	groups, err := s.ListGroups(ctx)
	if err != nil {
		t.Fatalf("list groups: %v", err)
	}
	clusters, err := s.ListClusters(ctx)
	if err != nil {
		t.Fatalf("list clusters: %v", err)
	}
	gotGroups := map[string][]string{}
	for _, g := range groups {
		gotGroups[g.Name] = g.Clusters
	}
	gotClusters := map[string][]string{}
	for _, c := range clusters {
		gotClusters[c.Name] = c.Groups
	}
	if diff := cmp.Diff(map[string][]string{"one": {"a", "b"}, "two": {"a", "c"}}, gotGroups); diff != "" {
		t.Errorf("groups mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(map[string][]string{"a": {"one", "two"}, "b": {"one"}, "c": {"two"}}, gotClusters); diff != "" {
		t.Errorf("clusters mismatch (-want +got):\n%s", diff)
	}
}
