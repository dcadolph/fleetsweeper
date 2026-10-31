package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestHandleListAcks_ReturnsStored verifies active acks are listed.
func TestHandleListAcks_ReturnsStored(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	if err := ss.SaveAck(context.Background(), store.AckRecord{
		Fingerprint: "fp-1", Cluster: "east", Scanner: "version",
		Title: "old k8s", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/acks", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "fp-1") {
		t.Errorf("expected seeded ack in body: %s", w.Body.String())
	}
}

// TestHandleCreateAck_Happy verifies a valid ack is persisted with the
// fingerprint taken from the path and the scope fields taken from the finding.
func TestHandleCreateAck_Happy(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	east, _ := seedAckFindings(t, srv, ss)
	req := httptest.NewRequest(http.MethodPost, "/api/findings/"+east.Fingerprint+"/ack",
		strings.NewReader(`{"ack_by":"op","reason":"known"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d body=%s", w.Code, w.Body.String())
	}
	acks, err := ss.ListAcks(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := []store.AckRecord{{
		Fingerprint: east.Fingerprint, Cluster: "east", Scanner: "workload-security",
		Title: east.Title, AckBy: "op", Reason: "known",
	}}
	if diff := cmp.Diff(want, acks, cmpopts.IgnoreFields(store.AckRecord{}, "CreatedAt")); diff != "" {
		t.Errorf("acks mismatch (-want +got):\n%s", diff)
	}
}

// TestHandleCreateAck_SnoozeRoundTrip verifies a valid RFC3339 snooze is
// stored on the record.
func TestHandleCreateAck_SnoozeRoundTrip(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	east, _ := seedAckFindings(t, srv, ss)
	snooze := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	body := `{"snooze_until":"` + snooze + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/findings/"+east.Fingerprint+"/ack",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d body=%s", w.Code, w.Body.String())
	}
	acks, _ := ss.ListAcks(context.Background())
	if len(acks) != 1 || acks[0].SnoozeUntil.IsZero() {
		t.Errorf("snooze not stored: %+v", acks)
	}
}

// TestHandleCreateAck_Validation covers the ack-create 400 branches.
func TestHandleCreateAck_Validation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name       string
		Path       bool
		Body       string
		WantStatus int
	}{{ // Test 0: Empty fingerprint.
		Name: "empty fp", Body: `{}`, WantStatus: http.StatusBadRequest,
	}, { // Test 1: Malformed JSON.
		Name: "bad json", Path: true, Body: "{", WantStatus: http.StatusBadRequest,
	}, { // Test 2: Malformed snooze timestamp.
		Name: "bad snooze", Path: true, Body: `{"snooze_until":"nope"}`,
		WantStatus: http.StatusBadRequest,
	}}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			srv, ss := testServer(t)
			east, _ := seedAckFindings(t, srv, ss)
			fp := ""
			if test.Path {
				fp = east.Fingerprint
			}
			req := httptest.NewRequest(http.MethodPost, "/api/findings/"+fp+"/ack",
				strings.NewReader(test.Body))
			req.SetPathValue("fingerprint", fp)
			req = req.WithContext(withActor(req.Context(), adminActor()))
			w := httptest.NewRecorder()
			srv.handleCreateAck(w, req)
			if w.Code != test.WantStatus {
				t.Errorf("want %d, got %d body=%s", test.WantStatus, w.Code, w.Body.String())
			}
		})
	}
}

// TestHandleDeleteAck covers the idempotent delete happy path and the
// empty-fingerprint 400.
func TestHandleDeleteAck(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	if err := ss.SaveAck(context.Background(), store.AckRecord{
		Fingerprint: "fp-del", Cluster: "east", Title: "t", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	del := httptest.NewRequest(http.MethodDelete, "/api/findings/fp-del/ack", nil)
	dw := httptest.NewRecorder()
	srv.mux.ServeHTTP(dw, del)
	if dw.Code != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d", dw.Code)
	}
	acks, _ := ss.ListAcks(context.Background())
	if len(acks) != 0 {
		t.Errorf("expected empty after delete, got %+v", acks)
	}

	empty := httptest.NewRequest(http.MethodDelete, "/api/findings//ack", nil)
	empty.SetPathValue("fingerprint", "")
	ew := httptest.NewRecorder()
	srv.handleDeleteAck(ew, empty)
	if ew.Code != http.StatusBadRequest {
		t.Errorf("empty fp: want 400, got %d", ew.Code)
	}
}

// TestAckSurvivesCountChange acks a finding through the API at one count and
// verifies the next scan, whose title carries a new count, serves it acked.
func TestAckSurvivesCountChange(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	ctx := context.Background()

	scanAt := func(privileged int) report.Finding {
		t.Helper()
		id, err := ss.SaveScan(ctx, []string{"a"}, map[string]map[string]scanner.Result{"a": {
			"workload-security": {Scanner: "workload-security", State: scanner.StateOK, Data: map[string]any{
				"privileged_containers": privileged, "total_pods": 10,
			}},
		}})
		if err != nil {
			t.Fatalf("seed scan: %v", err)
		}
		w := httptest.NewRecorder()
		srv.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/scans/"+id+"/report", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("get scan: want 200, got %d body=%s", w.Code, w.Body.String())
		}
		var rpt report.Report
		if err := json.Unmarshal(w.Body.Bytes(), &rpt); err != nil {
			t.Fatalf("decode report: %v", err)
		}
		for _, f := range rpt.Findings {
			if f.Rule == "workload-security/privileged" {
				return f
			}
		}
		t.Fatalf("no privileged finding in %+v", rpt.Findings)
		return report.Finding{}
	}

	first := scanAt(3)
	if first.Acked {
		t.Fatal("finding is acked before any ack")
	}
	req := httptest.NewRequest(http.MethodPost, "/api/findings/"+first.Fingerprint+"/ack", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("ack: want 201, got %d body=%s", w.Code, w.Body.String())
	}

	second := scanAt(4)
	if second.Title == first.Title {
		t.Fatalf("fixture titles must differ: %q", first.Title)
	}
	if !second.Acked {
		t.Errorf("finding %q is not acked at the new count", second.Title)
	}
}

// seedAckFindings saves one scan over east and west whose report carries a
// privileged-container finding on east and a version skew finding on the
// fleet, and returns both findings.
func seedAckFindings(t *testing.T, srv *Server, ss *store.SQLite) (report.Finding, report.Finding) {
	t.Helper()
	ctx := context.Background()
	version := func(v string) scanner.Result {
		return scanner.Result{Scanner: "version", State: scanner.StateOK, Data: map[string]any{"git_version": v}}
	}
	results := map[string]map[string]scanner.Result{
		"east": {
			"version": version("v1.29.0"),
			"workload-security": {Scanner: "workload-security", State: scanner.StateOK, Data: map[string]any{
				"privileged_containers": 3, "total_pods": 10,
			}},
		},
		"west": {"version": version("v1.28.3")},
	}
	if _, err := ss.SaveScan(ctx, []string{"east", "west"}, results); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	rpt := srv.latestReportForMetrics(ctx)
	if rpt == nil {
		t.Fatal("no latest report")
	}
	var east, fleet report.Finding
	for _, f := range rpt.Findings {
		switch {
		case f.Cluster == "east" && f.Rule == "workload-security/privileged":
			east = f
		case f.Cluster == "fleet" && f.Rule == "version/skew":
			fleet = f
		}
	}
	if east.Fingerprint == "" || fleet.Fingerprint == "" {
		t.Fatalf("seeded report lacks the east or fleet finding: %+v", rpt.Findings)
	}
	return east, fleet
}

// scopedOperator returns an operator Actor limited to the given cluster scope.
func scopedOperator(scope ...string) *Actor {
	return &Actor{ID: "op", Name: "op", Role: store.RoleOperator, ClusterScope: scope}
}

// TestHandleCreateAck_ServerOwnedScope verifies the ack route takes cluster,
// scanner, and title from the finding the server holds, checks the actor's
// scope against that cluster, and refuses fingerprints no finding carries.
func TestHandleCreateAck_ServerOwnedScope(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Actor      *Actor
		Target     string
		Body       string
		WantStatus int
		WantStored bool
	}{{ // Test 0: Out-of-scope operator omits the cluster from the body.
		Actor: scopedOperator("west"), Target: "east", Body: `{}`, WantStatus: http.StatusForbidden,
	}, { // Test 1: Out-of-scope operator names the fleet in the body.
		Actor: scopedOperator("west"), Target: "east", Body: `{"cluster":"fleet"}`,
		WantStatus: http.StatusForbidden,
	}, { // Test 2: Out-of-scope operator names its own cluster in the body.
		Actor: scopedOperator("west"), Target: "east", Body: `{"cluster":"west"}`,
		WantStatus: http.StatusForbidden,
	}, { // Test 3: Cluster-scoped operator acks a fleet-scoped finding.
		Actor: scopedOperator("east"), Target: "fleet", Body: `{}`, WantStatus: http.StatusForbidden,
	}, { // Test 4: In-scope operator acks its cluster's finding.
		Actor: scopedOperator("east"), Target: "east", Body: `{"ack_by":"op","reason":"known"}`,
		WantStatus: http.StatusCreated, WantStored: true,
	}, { // Test 5: Wildcard operator acks a fleet-scoped finding.
		Actor: scopedOperator(store.ScopeWildcard), Target: "fleet", Body: `{"reason":"skew"}`,
		WantStatus: http.StatusCreated, WantStored: true,
	}, { // Test 6: Fingerprint no current finding carries.
		Actor: adminActor(), Target: "unknown", Body: `{}`, WantStatus: http.StatusNotFound,
	}, { // Test 7: In-scope operator still may not name a cluster in the body.
		Actor: scopedOperator("east"), Target: "east", Body: `{"cluster":"east"}`,
		WantStatus: http.StatusBadRequest,
	}, { // Test 8: Empty body is accepted.
		Actor: scopedOperator("east"), Target: "east", Body: "",
		WantStatus: http.StatusCreated, WantStored: true,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			srv, ss := testServer(t)
			east, fleet := seedAckFindings(t, srv, ss)
			target := map[string]report.Finding{
				"east": east, "fleet": fleet,
				"unknown": {Fingerprint: "fp-unknown", Cluster: "east", Scanner: "spoof", Title: "spoof"},
			}[test.Target]
			req := httptest.NewRequest(http.MethodPost, "/api/findings/"+target.Fingerprint+"/ack",
				strings.NewReader(test.Body))
			req.SetPathValue("fingerprint", target.Fingerprint)
			req = req.WithContext(withActor(req.Context(), test.Actor))
			w := httptest.NewRecorder()
			srv.handleCreateAck(w, req)
			if w.Code != test.WantStatus {
				t.Fatalf("want %d, got %d body=%s", test.WantStatus, w.Code, w.Body.String())
			}
			acks, err := ss.ListAcks(context.Background())
			if err != nil {
				t.Fatalf("list acks: %v", err)
			}
			var want []store.AckRecord
			if test.WantStored {
				want = []store.AckRecord{{
					Fingerprint: target.Fingerprint, Cluster: target.Cluster,
					Scanner: target.Scanner, Title: target.Title,
				}}
			}
			ignore := cmpopts.IgnoreFields(store.AckRecord{}, "AckBy", "Reason", "SnoozeUntil", "CreatedAt")
			if diff := cmp.Diff(want, acks, ignore, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("stored acks mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestHandleDeleteAck_ServerOwnedScope verifies removing an ack checks the
// actor's scope against the cluster stored on the ack row.
func TestHandleDeleteAck_ServerOwnedScope(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Actor       *Actor
		Fingerprint string
		WantStatus  int
		WantAcked   bool
	}{{ // Test 0: Out-of-scope operator removes another cluster's ack.
		Actor: scopedOperator("west"), Fingerprint: "fp-east",
		WantStatus: http.StatusForbidden, WantAcked: true,
	}, { // Test 1: In-scope operator removes its cluster's ack.
		Actor: scopedOperator("east"), Fingerprint: "fp-east", WantStatus: http.StatusNoContent,
	}, { // Test 2: Cluster-scoped operator removes a fleet-scoped ack.
		Actor: scopedOperator("east"), Fingerprint: "fp-fleet",
		WantStatus: http.StatusForbidden, WantAcked: true,
	}, { // Test 3: Wildcard operator removes a fleet-scoped ack.
		Actor: scopedOperator(store.ScopeWildcard), Fingerprint: "fp-fleet",
		WantStatus: http.StatusNoContent,
	}, { // Test 4: Missing ack stays idempotent.
		Actor: scopedOperator("west"), Fingerprint: "fp-none", WantStatus: http.StatusNoContent,
	}, { // Test 5: Ack with no cluster needs wildcard scope.
		Actor: scopedOperator("east"), Fingerprint: "fp-blank",
		WantStatus: http.StatusForbidden, WantAcked: true,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			srv, ss := testServer(t)
			ctx := context.Background()
			seeds := map[string]string{"fp-east": "east", "fp-fleet": "fleet", "fp-blank": ""}
			for fp, cluster := range seeds {
				if err := ss.SaveAck(ctx, store.AckRecord{Fingerprint: fp, Cluster: cluster}); err != nil {
					t.Fatalf("seed ack: %v", err)
				}
			}
			req := httptest.NewRequest(http.MethodDelete, "/api/findings/"+test.Fingerprint+"/ack", nil)
			req.SetPathValue("fingerprint", test.Fingerprint)
			req = req.WithContext(withActor(req.Context(), test.Actor))
			w := httptest.NewRecorder()
			srv.handleDeleteAck(w, req)
			if w.Code != test.WantStatus {
				t.Fatalf("want %d, got %d body=%s", test.WantStatus, w.Code, w.Body.String())
			}
			acked, err := ss.IsAcked(ctx, test.Fingerprint)
			if err != nil {
				t.Fatalf("is acked: %v", err)
			}
			if acked != test.WantAcked {
				t.Errorf("acked = %v, want %v", acked, test.WantAcked)
			}
		})
	}
}
