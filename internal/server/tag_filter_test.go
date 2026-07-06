package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestParseTagFilter_NoQueryReturnsMatchAll verifies the predicate
// returned for a request with no `?tag=` parameters accepts every
// cluster.
func TestParseTagFilter_NoQueryReturnsMatchAll(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/scans/x/report", nil)
	allow, err := srv.parseTagFilter(req.Context(), req)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !allow("anything") || !allow("") {
		t.Error("empty tag filter should match all")
	}
}

// TestParseTagFilter_AndsMultipleTags verifies that two ?tag= entries
// require both to be present on a cluster.
func TestParseTagFilter_AndsMultipleTags(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	ctx := context.Background()
	_ = ss.SetClusterTag(ctx, "east", "env", "prod")
	_ = ss.SetClusterTag(ctx, "east", "tier", "critical")
	_ = ss.SetClusterTag(ctx, "west", "env", "prod")
	_ = ss.SetClusterTag(ctx, "dev", "env", "staging")

	req := httptest.NewRequest(http.MethodGet, "/api/scans/x/report?tag=env=prod&tag=tier=critical", nil)
	allow, err := srv.parseTagFilter(req.Context(), req)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !allow("east") {
		t.Error("east has env=prod and tier=critical; should match")
	}
	if allow("west") {
		t.Error("west has env=prod but no tier=critical; should not match")
	}
	if allow("dev") {
		t.Error("dev has env=staging; should not match")
	}
}

// TestListAlerts_TagFilterApplies verifies the /alerts endpoint
// honors ?tag= and excludes alerts on out-of-tag clusters.
func TestListAlerts_TagFilterApplies(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	ctx := context.Background()
	_ = ss.SetClusterTag(ctx, "east", "env", "prod")
	_ = ss.SetClusterTag(ctx, "dev", "env", "staging")

	for _, c := range []string{"east", "dev"} {
		if err := ss.UpsertAlert(ctx, store.AlertRecord{
			Fingerprint: "fp-" + c,
			Cluster:     c,
			Status:      "firing",
			AlertName:   "X",
			ReceivedAt:  time.Now(),
			Labels:      map[string]string{"cluster": c},
			Annotations: map[string]string{},
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	req := httptest.NewRequest(http.MethodGet,
		"/api/alerts?tag=env=prod", nil)
	w := httptest.NewRecorder()
	srv.handleListAlerts(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp struct {
		Alerts []store.AlertRecord `json:"alerts"`
		Count  int                 `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 1 || resp.Alerts[0].Cluster != "east" {
		t.Errorf("filter mismatch, expected just east: %+v", resp)
	}
}

// TestParseTagFilter_RejectsMalformedSilently verifies a malformed
// tag value (no equals sign) is dropped rather than failing the
// request. A purely-malformed query still falls through to
// "match all".
func TestParseTagFilter_RejectsMalformedSilently(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/scans/x/report?tag=bogus", nil)
	allow, err := srv.parseTagFilter(req.Context(), req)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !allow("anything") {
		t.Error("malformed filter should fall through to match-all")
	}
}
