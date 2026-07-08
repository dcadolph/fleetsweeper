package store

import (
	"context"
	"strings"
	"sync"
	"testing"
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
