package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner/crd"
)

// TestDemoLiveScan verifies a live demo scan keeps the requested clusters only and carries the
// scripted drift on even scans alone.
func TestDemoLiveScan(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Requested    []string
		WantClusters []string
		K            int
		WantDrift    bool
	}{{ // Test 0: The first live scan of the whole fleet carries the drift.
		Requested: demoClusterNames(), WantClusters: demoClusterNames(), K: 0, WantDrift: true,
	}, { // Test 1: The second restores it.
		Requested: demoClusterNames(), WantClusters: demoClusterNames(), K: 1,
	}, { // Test 2: A subset keeps fleet order and drops names outside the fleet.
		Requested:    []string{"edge-lagos", "nope", demoDriftCluster},
		WantClusters: []string{demoDriftCluster, "edge-lagos"}, K: 2, WantDrift: true,
	}, { // Test 3: Nothing requested scans nothing.
		WantClusters: []string{}, K: 0,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			clusters, results := demoLiveScan(test.K, test.Requested, demoTestNow)
			if diff := cmp.Diff(test.WantClusters, clusters); diff != "" {
				t.Errorf("clusters mismatch (-want +got):\n%s", diff)
			}
			if len(results) != len(clusters) {
				t.Errorf("want results for %d clusters, got %d", len(clusters), len(results))
			}
			res, ok := results[demoDriftCluster][crd.Name]
			if !ok {
				return
			}
			d, _ := res.Data.(crd.Data)
			hasGroup := slices.ContainsFunc(d.CRDs, func(c crd.CRDInfo) bool { return c.Group == demoDriftGroup })
			if hasGroup == test.WantDrift {
				t.Errorf("drift %v: %s group present = %v", test.WantDrift, demoDriftGroup, hasGroup)
			}
			if d.Count != len(d.CRDs) {
				t.Errorf("count %d disagrees with %d CRDs", d.Count, len(d.CRDs))
			}
		})
	}
}

// TestDemoTriggerScanLive verifies a scan triggered in demo mode with no token scans the
// synthetic fleet, publishes scan.complete, and that the drift it lands shows as a finding on
// the next report and clears on the scan after.
func TestDemoTriggerScanLive(t *testing.T) {
	t.Parallel()
	srv := newSealedDemoServer(t)
	events, unsub := srv.events.subscribe(8)
	defer unsub()

	trigger := func() string {
		t.Helper()
		body, _ := json.Marshal(triggerScanRequest{AllContexts: true})
		w := httptest.NewRecorder()
		srv.mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/scans", bytes.NewReader(body)))
		if w.Code != http.StatusAccepted {
			t.Fatalf("trigger: want 202, got %d body=%s", w.Code, w.Body.String())
		}
		var resp triggerScanResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode trigger response: %v", err)
		}
		waitForScan(t, srv, resp.ScanID)
		srv.bg.Wait()
		select {
		case ev := <-events:
			payload, _ := ev.Payload.(map[string]any)
			if ev.Type != EventScanComplete || payload["scan_id"] != resp.ScanID {
				t.Fatalf("want scan.complete for %s, got %s %v", resp.ScanID, ev.Type, ev.Payload)
			}
			if payload["clusters"] != len(demoClusterNames()) {
				t.Errorf("want %d clusters in the event, got %v", len(demoClusterNames()), payload["clusters"])
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no scan.complete event")
		}
		return resp.ScanID
	}
	drifted := func(id string) bool {
		t.Helper()
		w := httptest.NewRecorder()
		srv.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/scans/"+id+"/report", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("report %s: want 200, got %d", id, w.Code)
		}
		var rpt struct {
			Findings []report.Finding `json:"findings"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &rpt); err != nil {
			t.Fatalf("decode report: %v", err)
		}
		return slices.ContainsFunc(rpt.Findings, func(f report.Finding) bool {
			return f.Cluster == demoDriftCluster && f.Scanner == crd.Name &&
				strings.Contains(fmt.Sprint(f.Affected, f.Description, f.Norm), demoDriftGroup)
		})
	}

	if first := trigger(); !drifted(first) {
		t.Errorf("first live scan %s: want a %s finding on %s", first, demoDriftGroup, demoDriftCluster)
	}
	if second := trigger(); drifted(second) {
		t.Errorf("second live scan %s: want the %s drift cleared", second, demoDriftGroup)
	}
}
