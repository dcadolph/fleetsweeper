package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// timelineResponse mirrors the JSON returned by handleFindingsTimeline.
type timelineResponse struct {
	Scans  int             `json:"scans"`
	Points []timelinePoint `json:"points"`
}

// persistenceResponse mirrors the JSON returned by handleFindingsPersistence.
type persistenceResponse struct {
	Scans        int                         `json:"scans"`
	Chronic      int                         `json:"chronic"`
	Intermittent int                         `json:"intermittent"`
	Transient    int                         `json:"transient"`
	Findings     []report.FindingPersistence `json:"findings"`
}

// replayGetJSON issues a GET against the server mux and decodes a 200 body.
func replayGetJSON(t *testing.T, srv *Server, path string, out any) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code == http.StatusOK && out != nil {
		if err := json.NewDecoder(w.Body).Decode(out); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
	}
	return w.Code
}

// TestFindingsTimelineDemo checks the timeline endpoint honors the scans window
// (default and upper bound), orders points oldest to newest, and reconciles the
// per-severity counts against the total in each point.
func TestFindingsTimelineDemo(t *testing.T) {
	t.Parallel()
	srv := newDemoServer(t)

	tests := []struct {
		Query     string
		WantCount int
	}{
		{Query: "", WantCount: replayDefaultScans},       // Test 0: Default window.
		{Query: "?scans=12", WantCount: 12},              // Test 1: Explicit window.
		{Query: "?scans=999", WantCount: replayMaxScans}, // Test 2: Clamped to the cap.
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			var resp timelineResponse
			if code := replayGetJSON(t, srv, "/api/findings/timeline"+test.Query, &resp); code != http.StatusOK {
				t.Fatalf("status: want 200, got %d", code)
			}
			if resp.Scans != test.WantCount || len(resp.Points) != test.WantCount {
				t.Fatalf("count: want %d, got scans=%d points=%d", test.WantCount, resp.Scans, len(resp.Points))
			}

			var last string
			for i, p := range resp.Points {
				if p.Critical+p.Warning+p.Info != p.Total {
					t.Errorf("point %d severity counts %d+%d+%d != total %d", i, p.Critical, p.Warning, p.Info, p.Total)
				}
				if p.Timestamp <= last {
					t.Errorf("point %d timestamp %q not after previous %q", i, p.Timestamp, last)
				}
				last = p.Timestamp
				for _, f := range p.Findings {
					if f.Fingerprint == "" {
						t.Errorf("point %d finding %q missing fingerprint", i, f.Title)
					}
				}
			}
		})
	}
}

// TestFindingsTimelineShowsDrift verifies the synthesized demo series actually
// drifts: finding counts are not identical across the whole window.
func TestFindingsTimelineShowsDrift(t *testing.T) {
	t.Parallel()
	srv := newDemoServer(t)

	var resp timelineResponse
	if code := replayGetJSON(t, srv, "/api/findings/timeline?scans=24", &resp); code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", code)
	}
	if len(resp.Points) < 2 {
		t.Fatalf("need multiple points, got %d", len(resp.Points))
	}

	allSame := true
	first := resp.Points[0].Total
	for _, p := range resp.Points {
		if p.Total != first {
			allSame = false
			break
		}
	}
	if allSame {
		t.Error("expected finding counts to vary across the replay window (no drift observed)")
	}
}

// TestFindingsPersistenceDemo checks the persistence endpoint classifies demo
// findings, sorts them most-persistent first, keeps every field in range, and
// reconciles the class counts.
func TestFindingsPersistenceDemo(t *testing.T) {
	t.Parallel()
	srv := newDemoServer(t)

	var resp persistenceResponse
	if code := replayGetJSON(t, srv, "/api/findings/persistence?scans=24", &resp); code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", code)
	}
	if resp.Scans != 24 {
		t.Fatalf("scans: want 24, got %d", resp.Scans)
	}
	if len(resp.Findings) == 0 {
		t.Fatal("expected persistence findings from the demo series")
	}
	if resp.Chronic+resp.Intermittent+resp.Transient != len(resp.Findings) {
		t.Errorf("class counts %d+%d+%d != findings %d", resp.Chronic, resp.Intermittent, resp.Transient, len(resp.Findings))
	}

	prev := 2.0
	maxStreak := 0
	for i, p := range resp.Findings {
		if p.Total != 24 {
			t.Errorf("finding %d total: want 24, got %d", i, p.Total)
		}
		if p.Present < 1 || p.Present > p.Total {
			t.Errorf("finding %d present %d out of range 1..%d", i, p.Present, p.Total)
		}
		if p.Fraction <= 0 || p.Fraction > 1 {
			t.Errorf("finding %d fraction %v out of range", i, p.Fraction)
		}
		if p.Streak < 0 || p.Streak > p.Present {
			t.Errorf("finding %d streak %d exceeds present %d", i, p.Streak, p.Present)
		}
		if p.Fraction > prev {
			t.Errorf("findings not sorted by fraction desc at %d: %v > %v", i, p.Fraction, prev)
		}
		prev = p.Fraction
		if p.Streak > maxStreak {
			maxStreak = p.Streak
		}
		switch p.Class {
		case report.PersistenceChronic, report.PersistenceIntermittent, report.PersistenceTransient:
		default:
			t.Errorf("finding %d unknown class %q", i, p.Class)
		}
	}
	if maxStreak < 1 {
		t.Error("expected at least one finding present in the most recent scan")
	}
}
