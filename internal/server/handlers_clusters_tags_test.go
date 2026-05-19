package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestListClusters_IncludesTags verifies the augmented handler folds
// the cluster_tags rows into each ClusterRecord on the wire.
func TestListClusters_IncludesTags(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	ctx := context.Background()
	if _, err := ss.SaveScan(ctx, []string{"east", "west"}, map[string]map[string]scanner.Result{
		"east": {"version": {Scanner: "version", Data: map[string]any{"v": "1"}}},
		"west": {"version": {Scanner: "version", Data: map[string]any{"v": "1"}}},
	}); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	_ = ss.SetClusterTag(ctx, "east", "env", "prod")
	_ = ss.SetClusterTag(ctx, "east", "tier", "critical")

	req := httptest.NewRequest(http.MethodGet, "/api/clusters", nil)
	w := httptest.NewRecorder()
	srv.handleListClusters(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var got []store.ClusterRecord
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byName := map[string]store.ClusterRecord{}
	for _, c := range got {
		byName[c.Name] = c
	}
	if byName["east"].Tags["env"] != "prod" || byName["east"].Tags["tier"] != "critical" {
		t.Errorf("east tags missing: %+v", byName["east"])
	}
	if len(byName["west"].Tags) != 0 {
		t.Errorf("west should have no tags: %+v", byName["west"])
	}
}
