package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/controller"
	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestHandleTriggerScan_Paths covers the synchronous validation and
// authorization branches of the scan-trigger handler without launching a
// real scan goroutine. The busy case is exercised by pre-setting the
// in-flight flag so CompareAndSwap short-circuits to 429.
func TestHandleTriggerScan_Paths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name       string
		Body       string
		Actor      *Actor
		Busy       bool
		WantStatus int
	}{{ // Test 0: Malformed JSON body.
		Name: "bad json", Body: "{", Actor: adminActor(), WantStatus: http.StatusBadRequest,
	}, { // Test 1: Empty context list.
		Name: "no contexts", Body: `{"contexts":[]}`, Actor: adminActor(),
		WantStatus: http.StatusBadRequest,
	}, { // Test 2: Group that does not exist.
		Name: "unknown group", Body: `{"group":"ghost"}`, Actor: adminActor(),
		WantStatus: http.StatusBadRequest,
	}, { // Test 3: Requested contexts all outside actor scope.
		Name: "scope filters all", Body: `{"contexts":["east"]}`,
		Actor:      &Actor{ID: "s", Role: store.RoleOperator, ClusterScope: []string{"west"}},
		WantStatus: http.StatusForbidden,
	}, { // Test 4: A scan already in progress yields 429.
		Name: "busy", Body: `{"contexts":["east"]}`, Actor: adminActor(), Busy: true,
		WantStatus: http.StatusTooManyRequests,
	}}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			srv, _ := testServer(t)
			if test.Busy {
				srv.scanBusy.Store(true)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/scans",
				strings.NewReader(test.Body))
			req = req.WithContext(withActor(req.Context(), test.Actor))
			w := httptest.NewRecorder()
			srv.handleTriggerScan(w, req)
			if w.Code != test.WantStatus {
				t.Errorf("want %d, got %d body=%s", test.WantStatus, w.Code, w.Body.String())
			}
		})
	}
}

// TestHandleAdminCreateKey_Validation covers the create-key 400 branches and
// the TTL parsing path.
func TestHandleAdminCreateKey_Validation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name       string
		Body       string
		WantStatus int
	}{{ // Test 0: Malformed JSON.
		Name: "bad json", Body: "{", WantStatus: http.StatusBadRequest,
	}, { // Test 1: Missing name.
		Name: "empty name", Body: `{"role":"viewer"}`, WantStatus: http.StatusBadRequest,
	}, { // Test 2: Invalid role.
		Name: "bad role", Body: `{"name":"x","role":"wizard"}`, WantStatus: http.StatusBadRequest,
	}, { // Test 3: Malformed TTL duration.
		Name: "bad ttl", Body: `{"name":"x","role":"viewer","ttl":"forever"}`,
		WantStatus: http.StatusBadRequest,
	}, { // Test 4: Valid request with TTL.
		Name: "valid ttl", Body: `{"name":"ci","role":"operator","ttl":"24h"}`,
		WantStatus: http.StatusCreated,
	}}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			srv, _ := testServer(t)
			req := httptest.NewRequest(http.MethodPost, "/api/admin/keys",
				strings.NewReader(test.Body))
			req = req.WithContext(withActor(req.Context(), adminActor()))
			w := httptest.NewRecorder()
			srv.handleAdminCreateKey(w, req)
			if w.Code != test.WantStatus {
				t.Errorf("want %d, got %d body=%s", test.WantStatus, w.Code, w.Body.String())
			}
		})
	}
}

// TestHandleListContexts_NonDemo verifies the non-demo path returns 200 with
// a JSON array even when no kubeconfig contexts are reachable.
func TestHandleListContexts_NonDemo(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.kubeconfigPath = "/nonexistent/kubeconfig-for-test"
	req := httptest.NewRequest(http.MethodGet, "/api/contexts", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if !strings.HasPrefix(strings.TrimSpace(w.Body.String()), "[") {
		t.Errorf("expected JSON array, got %s", w.Body.String())
	}
}

// TestHandleGetCohorts_NoScans verifies the empty-store 404 path.
func TestHandleGetCohorts_NoScans(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/cohorts", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

// TestHandleClusterTimeline_ScopeRejected verifies a scoped actor cannot read
// a timeline for a cluster outside its scope.
func TestHandleClusterTimeline_ScopeRejected(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/clusters/east/timeline", nil)
	req.SetPathValue("name", "east")
	scoped := &Actor{ID: "s", Role: store.RoleOperator, ClusterScope: []string{"west"}}
	req = req.WithContext(withActor(req.Context(), scoped))
	w := httptest.NewRecorder()
	srv.handleClusterTimeline(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", w.Code)
	}
}

// writeTestKubeconfig writes a kubeconfig whose contexts all point at an address nothing
// listens on. Clients build without contacting the server, so fake scanners can run against
// them, while a real scanner would fail to connect.
func writeTestKubeconfig(t *testing.T, contexts ...string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: Config\nclusters:\n- name: c\n  cluster:\n    server: http://127.0.0.1:9\n")
	b.WriteString("users:\n- name: u\n  user: {}\ncontexts:\n")
	for _, c := range contexts {
		fmt.Fprintf(&b, "- name: %s\n  context:\n    cluster: c\n    user: u\n", c)
	}
	if len(contexts) > 0 {
		fmt.Fprintf(&b, "current-context: %s\n", contexts[0])
	}
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return path
}

// pressureScanner is a fake node-health scanner reporting one node under memory pressure, which
// the report turns into one critical finding per cluster.
var pressureScanner = scanner.Func(func(context.Context, *kube.Client) (scanner.Result, error) {
	return scanner.Result{Scanner: "node-health", Data: map[string]any{
		"node_count": 3, "healthy_nodes": 2, "memory_pressure_nodes": 1,
	}}, nil
})

// newScanTestServer builds a server whose registry holds only pressureScanner and whose
// kubeconfig defines the given contexts.
func newScanTestServer(t *testing.T, contexts ...string) (*Server, *store.SQLite) {
	t.Helper()
	srv, ss := testServer(t)
	reg := scanner.NewRegistry()
	reg.Register("node-health", pressureScanner)
	srv.registry = reg
	srv.kubeconfigPath = writeTestKubeconfig(t, contexts...)
	return srv, ss
}

// waitForScan polls GET /api/scans/{id} until it resolves.
func waitForScan(t *testing.T, srv *Server, id string) {
	t.Helper()
	start := time.Now()
	for time.Since(start) < 10*time.Second {
		req := httptest.NewRequest(http.MethodGet, "/api/scans/"+id, nil)
		w := httptest.NewRecorder()
		srv.mux.ServeHTTP(w, req)
		if w.Code == http.StatusOK {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("scan %s never resolved", id)
}

// triggerScan posts a scan of contexts and returns the scan ID from the 202 response.
func triggerScan(t *testing.T, srv *Server, contexts ...string) string {
	t.Helper()
	body, _ := json.Marshal(triggerScanRequest{Contexts: contexts})
	req := httptest.NewRequest(http.MethodPost, "/api/scans", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("trigger: want 202, got %d body=%s", w.Code, w.Body.String())
	}
	var resp triggerScanResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode trigger response: %v", err)
	}
	if resp.ScanID == "" || resp.Status != "running" {
		t.Fatalf("trigger response: want a scan_id and running, got %+v", resp)
	}
	return resp.ScanID
}

// TestTriggerScanReturnsResolvableID verifies the trigger response carries the ID the scan is
// saved under, that it resolves at /api/scans/{id}, and that the completion event names it.
func TestTriggerScanReturnsResolvableID(t *testing.T) {
	t.Parallel()
	srv, ss := newScanTestServer(t, "east", "west")
	events, unsub := srv.events.subscribe(8)
	defer unsub()

	id := triggerScan(t, srv, "east", "west")
	waitForScan(t, srv, id)

	select {
	case ev := <-events:
		payload, _ := ev.Payload.(map[string]any)
		if ev.Type != EventScanComplete || payload["scan_id"] != id || payload["source"] != scanSourceTriggered {
			t.Errorf("want scan.complete for %s from triggered, got %s %v", id, ev.Type, ev.Payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no scan.complete event")
	}
	rec, err := ss.GetScan(context.Background(), id)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if diff := cmp.Diff([]string{"east", "west"}, rec.Clusters, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
		t.Errorf("clusters mismatch (-want +got):\n%s", diff)
	}
	srv.bg.Wait()
	if got := srv.scansOK.Load(); got != 1 {
		t.Errorf("want 1 successful scan counted, got %d", got)
	}
}

// TestSlowWebhookDoesNotDelaySecondScan verifies notification delivery runs after scanMu is
// released, so a subscriber that takes 2s to answer does not hold up the next scan.
func TestSlowWebhookDoesNotDelaySecondScan(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(slow.Close)
	cfg := filepath.Join(t.TempDir(), "webhooks.yaml")
	yaml := "webhooks:\n- name: slow\n  url: " + slow.URL + "\n  min_severity: critical\n"
	if err := os.WriteFile(cfg, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write webhook config: %v", err)
	}

	srv, _ := newScanTestServer(t, "east", "west")
	srv.setupWebhooks(cfg)
	if srv.webhookDispatcher == nil {
		t.Fatal("webhook dispatcher not configured")
	}

	first := triggerScan(t, srv, "east")
	waitForScan(t, srv, first)
	deadline := time.Now().Add(5 * time.Second)
	for (srv.scanBusy.Load() || hits.Load() == 0) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if hits.Load() == 0 {
		t.Fatal("first scan never reached the webhook subscriber")
	}

	started := time.Now()
	second := triggerScan(t, srv, "west")
	waitForScan(t, srv, second)
	if took := time.Since(started); took > time.Second {
		t.Errorf("second scan took %v while the first scan's webhook was still sending", took)
	}
}

// TestExecuteScanFailureIsCounted verifies a scan with no reachable cluster is counted as a
// failure, publishes scan.failed, and saves nothing.
func TestExecuteScanFailureIsCounted(t *testing.T) {
	t.Parallel()
	srv, ss := newScanTestServer(t, "east")
	events, unsub := srv.events.subscribe(8)
	defer unsub()

	id, rpt, err := srv.executeScan(context.Background(), scanRequest{
		Source: scanSourceScheduled, Contexts: []string{"not-in-kubeconfig"}, Emit: emitAll,
	})
	if !errors.Is(err, errNoClusters) {
		t.Fatalf("want errNoClusters, got %v", err)
	}
	if id == "" || rpt != nil {
		t.Errorf("want an allocated id and no report, got %q %v", id, rpt)
	}
	if got := srv.scansErr.Load(); got != 1 {
		t.Errorf("want 1 failed scan counted, got %d", got)
	}
	select {
	case ev := <-events:
		if ev.Type != EventScanFailed {
			t.Errorf("want scan.failed, got %s", ev.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("no scan.failed event")
	}
	if _, err := ss.GetScan(context.Background(), id); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a failed scan must not be saved, got %v", err)
	}
}

// TestScanOnceHonorsEmitOptions verifies the controller path returns a summary for the saved
// scan and posts to Slack only when its ClusterScan asks for it.
func TestScanOnceHonorsEmitOptions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Emit      controller.EmitOptions
		WantPosts int64
	}{{ // Test 0: Slack off.
		Emit: controller.EmitOptions{}, WantPosts: 0,
	}, { // Test 1: Slack on.
		Emit: controller.EmitOptions{Slack: true}, WantPosts: 1,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			var posts atomic.Int64
			slack := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
				posts.Add(1)
			}))
			t.Cleanup(slack.Close)
			srv, ss := newScanTestServer(t, "east", "west")
			srv.slackWebhookURL = slack.URL

			sum, err := srv.ScanOnce(context.Background(), controller.ScanOptions{
				Contexts: []string{"east", "west"}, Emit: test.Emit, ResourceName: "cs",
			})
			if err != nil {
				t.Fatalf("scan once: %v", err)
			}
			if _, err := ss.GetScan(context.Background(), sum.ScanID); err != nil {
				t.Errorf("summary scan id does not resolve: %v", err)
			}
			if sum.Clusters != 2 || sum.Critical != 2 {
				t.Errorf("want 2 clusters and 2 criticals, got %+v", sum)
			}
			srv.bg.Wait()
			if got := posts.Load(); got != test.WantPosts {
				t.Errorf("want %d Slack posts, got %d", test.WantPosts, got)
			}
		})
	}
}

// TestExecuteScanUsesTagsAndGroups verifies every scan's report is built with the stored cohort
// tags and groups, which only the controller path did before.
func TestExecuteScanUsesTagsAndGroups(t *testing.T) {
	t.Parallel()
	srv, ss := newScanTestServer(t, "east", "west")
	ctx := context.Background()
	if err := ss.SetClusterTag(ctx, "east", cohortTagKey, "edge"); err != nil {
		t.Fatalf("set tag: %v", err)
	}
	if err := ss.SaveGroup(ctx, "prod", []string{"east", "west"}); err != nil {
		t.Fatalf("save group: %v", err)
	}

	opts := srv.reportOptions(ctx, zap.NewNop())
	if diff := cmp.Diff(map[string]string{"east": "edge"}, opts.ClusterTags); diff != "" {
		t.Errorf("tags mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(map[string][]string{"prod": {"east", "west"}}, opts.Groups); diff != "" {
		t.Errorf("groups mismatch (-want +got):\n%s", diff)
	}

	_, rpt, err := srv.executeScan(ctx, scanRequest{Source: scanSourceScheduled, Contexts: []string{"east", "west"}})
	if err != nil {
		t.Fatalf("execute scan: %v", err)
	}
	var tagged bool
	for _, c := range rpt.Cohorts {
		if c.Source == "tagged" && c.Name == "edge" {
			tagged = true
		}
	}
	if !tagged {
		t.Errorf("want a tagged cohort named edge, got %+v", rpt.Cohorts)
	}
}
